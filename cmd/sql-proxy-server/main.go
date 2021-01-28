package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/planetscale/sql-proxy/sigutil"
	"go.uber.org/zap"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	organizationNameLabel             = "organization-name"
	databaseBranchCollectionNameLabel = "database-branch-collection-name"
	databaseBranchNameLabel           = "database-branch-name"
	psComponentLabel                  = "planetscale.com/component"

	// expireTTL defines the time a kubernetes service address expires in the
	// cache.
	expireTTL = 1 * time.Minute
)

var (
	commit       string
	gitTreeState string

	errAddrNotFound = errors.New("remote address not found")
)

type server struct {
	cfg         *tls.Config
	localAddr   string
	backendAddr string
	log         *zap.Logger

	// k8s bits
	kubeClient client.Client
	namespace  string

	// svcCache contains the vtgate address cache for each individual
	// org/db/branch combination
	addrCache *addrCache
}

func main() {
	if err := realMain(); err != nil {
		zap.L().Fatal("exiting sql-proxy-server", zap.Error(err))
	}
}

func realMain() error {
	caPath := flag.String("ca-file", "", "MySQL CA Cert path")
	serverCertPath := flag.String("cert-file", "", "MySQL server Cert path")
	serverKeyPath := flag.String("key-file", "", "MySQL server Key path")

	// backendAddr is used to manually override the routing that is done
	// otherwise via kubernetes services. Useful for manual testing.
	backendAddr := flag.String("backend-addr", "", "MySQL backend network address")
	localAddr := flag.String("local-addr", "127.0.0.1:3308", "Local address to bind and listen")
	kubeNamespace := flag.String("kube-namespace", "default", "Namespace in which the target vtgate Services are deployed.")

	flag.Parse()

	if *caPath == "" || *serverCertPath == "" || *serverKeyPath == "" {
		return errors.New("-ca-file, -cert-file or -key-file is empty")
	}

	caBuf, err := ioutil.ReadFile(*caPath)
	if err != nil {
		return err
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(caBuf)

	certs, err := tls.LoadX509KeyPair(*serverCertPath, *serverKeyPath)
	if err != nil {
		return err
	}

	cfg := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		ClientCAs:                rootCertPool,
		Certificates:             []tls.Certificate{certs},
		ClientAuth:               tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			commonName := cs.PeerCertificates[0].Subject.CommonName
			if commonName != cs.ServerName {
				return fmt.Errorf("invalid certificate name %q, expected %q", commonName, cs.ServerName)
			}
			opts := x509.VerifyOptions{
				Roots:         rootCertPool,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}

	// TODO(fatih): replace with signal.NotifyContext once Go 1.16 is released
	// https://go-review.googlesource.com/c/go/+/219640
	ctx := sigutil.WithSignal(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	logger, err := zap.NewProduction(
		zap.Fields(zap.String("app", "sql-proxy-server")),
	)
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(logger)

	srv := &server{
		cfg:         cfg,
		namespace:   *kubeNamespace,
		localAddr:   *localAddr,
		backendAddr: *backendAddr,
		addrCache:   newAddrCache(),
		log:         logger,
	}

	if *backendAddr != "" {
		srv.log.Info("disabling kube client, using the provided backend addressn",
			zap.String("backend_addr", *backendAddr))
		srv.backendAddr = *backendAddr
	} else {
		srv.log.Info("initalized kube client")
		srv.kubeClient, err = newKubeClient()
		if err != nil {
			return err
		}
	}

	srv.log.Info("ready for new connections",
		zap.String("commit", commit),
		zap.String("git_tree_state", gitTreeState),
		zap.String("local_addr", srv.localAddr),
	)
	return srv.Run(ctx)
}

// Run runs the server proxy
func (s *server) Run(ctx context.Context) error {
	l, err := net.Listen("tcp", s.localAddr)
	if err != nil {
		return err
	}
	defer l.Close()

	return s.run(ctx, l)
}

// run runs the server proxy. This is an unexported function to make testing
// usable.
func (s *server) run(ctx context.Context, l net.Listener) error {
	for {
		select {
		case <-ctx.Done():
			termTimeout := time.Second * 1
			s.log.Info("received context cancellation, waiting until timeout",
				zap.Duration("timeout", termTimeout))
			return nil
		default:
			c, err := l.Accept()
			if err != nil {
				return err
			}
			defer l.Close()

			go func() {
				if err := s.handleConn(ctx, c); err != nil {
					s.log.Error("error proxying conns", zap.Error(err))
				}
			}()
		}
	}
}

// handleConn proxies the given connection to the appropriate vtgate cluster
// based on the information baked into CN.
func (s *server) handleConn(ctx context.Context, conn net.Conn) error {
	tlsConn := tls.Server(conn, s.cfg)

	// normally this is done automatically, but we need to access to
	// ConnectionState, which is only populated after a successfull
	// handshake
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()

		if err == io.EOF {
			if c, ok := conn.(*net.TCPConn); ok {
				s.log.Debug("io EOF error",
					zap.String("remote_addr", c.RemoteAddr().String()),
				)
			}
			// non-TLS clients, such as healt-checks will end here, don't
			// return an error
			return nil
		}

		return fmt.Errorf("couldn't establish a TLS handshake: %s", err)
	}

	cn := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
	s.log.Info("new connection received with CN", zap.String("common_name", cn))

	st := strings.Split(cn, "/")
	if len(st) != 3 {
		return fmt.Errorf("CN instance format is malformed, should be in form organization/dbname/branch, have: %q", cn)
	}

	org, db, branch := st[0], st[1], st[2]

	vtgateAddr := s.backendAddr
	if vtgateAddr == "" {
		serviceAddr, err := s.getServiceAddr(ctx, org, db, branch)
		if err != nil {
			return err
		}

		vtgateAddr = serviceAddr
	}

	var d net.Dialer
	backendConn, err := d.DialContext(ctx, "tcp", vtgateAddr) // mysql instance
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("couldn't connect to backend: %s", err)
	}

	switch c := backendConn.(type) {
	case *net.TCPConn:
		c.SetKeepAlive(true)                  //nolint: errcheck
		c.SetKeepAlivePeriod(1 * time.Minute) //nolint: errcheck
	}

	copyThenClose(backendConn, tlsConn, "remote conn", "local conn on "+vtgateAddr)
	return nil
}

func copyThenClose(remote, local io.ReadWriteCloser, remoteDesc, localDesc string) {
	firstErr := make(chan error, 1)

	go func() {
		readErr, err := myCopy(remote, local)
		select {
		case firstErr <- err:
			if readErr && err == io.EOF {
				zap.L().Info("client closed connection",
					zap.String("local_desc", localDesc))
			} else {
				logError(localDesc, remoteDesc, readErr, err)
			}
			remote.Close()
			local.Close()
		default:
		}
	}()

	readErr, err := myCopy(local, remote)
	select {
	case firstErr <- err:
		if readErr && err == io.EOF {
			zap.L().Info("instance closed connection",
				zap.String("remote_desc", remoteDesc))
		} else {
			logError(remoteDesc, localDesc, readErr, err)
		}
		remote.Close()
		local.Close()
	default:
		// In this case, the other goroutine exited first and already printed its
		// error (and closed the things).
	}
}

// myCopy is similar to io.Copy, but reports whether the returned error was due
// to a bad read or write. The returned error will never be nil
func myCopy(dst io.Writer, src io.Reader) (readErr bool, err error) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				if err == nil {
					return false, werr
				}
				// Read and write error; just report read error (it happened first).
				return true, err
			}
		}
		if err != nil {
			return true, err
		}
	}
}

func logError(readDesc, writeDesc string, readErr bool, err error) {
	var desc string
	if readErr {
		desc = "reading data from " + readDesc
	} else {
		desc = "writing data to " + writeDesc
	}
	zap.L().Error("copy error", zap.String("desc", desc), zap.Error(err))
}

func newKubeClient() (client.Client, error) {
	restConfig, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("can't parse kubeconfig: %v", err)
	}

	var (
		// supportedK8sSchemeAddFuncs determines which resources we register in our k8s client.
		supportedK8sSchemeAddFuncs = []func(*runtime.Scheme) error{
			// core/v1, apps/v1 etc.
			k8sscheme.AddToScheme,
		}
	)

	scheme := runtime.NewScheme()
	for _, addFunc := range supportedK8sSchemeAddFuncs {
		if err := addFunc(scheme); err != nil {
			return nil, fmt.Errorf("can't add resources to scheme: %v", err)
		}
	}

	mapper, err := apiutil.NewDiscoveryRESTMapper(restConfig)
	if err != nil {
		return nil, fmt.Errorf("can't create DiscoveryRESTMapper: %v", err)
	}

	cl, err := client.New(restConfig, client.Options{
		Scheme: scheme,
		Mapper: mapper,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %s", err)
	}

	return cl, nil
}

func (s *server) getServiceAddr(ctx context.Context, org, db, branch string) (string, error) {
	addr, err := s.addrCache.Get("")
	if err == nil {
		log.Println("using address from the cache")
		return addr, nil
	}

	selector := labels.Set{
		organizationNameLabel:             org,
		databaseBranchCollectionNameLabel: db,
		databaseBranchNameLabel:           branch,
		psComponentLabel:                  "vtgate",
	}.AsSelector()

	listOpts := &client.ListOptions{
		Namespace:     s.namespace,
		LabelSelector: selector,
	}

	list := &v1.ServiceList{}
	if err := s.kubeClient.List(ctx, list, listOpts); err != nil {
		return "", fmt.Errorf("couldn't list services found for '%s/%s/%s': %s",
			org, db, branch, err)
	}

	if len(list.Items) == 0 {
		return "", fmt.Errorf("no services found for '%s/%s/%s'",
			org, db, branch)
	}

	svc := list.Items[0]

	if len(svc.Spec.Ports) == 0 {
		return "", fmt.Errorf("there are no ports defined for the service: %q", svc.Name)
	}

	var port int32
	for _, p := range svc.Spec.Ports {
		if p.Name == "mysql" {
			port = p.Port
		}
	}

	if port == 0 {
		return "", errors.New("couldn't find a service port named 'mysql'")
	}

	addr = fmt.Sprintf("%s:%d", svc.Spec.ClusterIP, port)
	s.addrCache.Add("", addr)

	return addr, nil
}

type cacheEntry struct {
	// addr defines the vtgate/remote addr the proxy will connect
	addr string

	// added holds the time the address was added to the cache
	added time.Time
}

type addrCache struct {
	// addrs holds the remote addresses for each odb id.
	addrs   map[string]cacheEntry
	addrsMu sync.Mutex // protects addrs

	// nowFn returns the current local time, used during insertion of cache
	// entries. It's a function so we can use it for tests.
	nowFn func() time.Time
}

func newAddrCache() *addrCache {
	return &addrCache{
		addrs: make(map[string]cacheEntry),
		nowFn: time.Now,
	}
}

// Add adds the given addr for the given instance name
func (a *addrCache) Add(instance, addr string) {
	a.addrsMu.Lock()
	defer a.addrsMu.Unlock()

	a.addrs[instance] = cacheEntry{
		addr:  addr,
		added: a.nowFn(),
	}
}

// Get retrieves the address for the given instance
func (a *addrCache) Get(instance string) (string, error) {
	a.addrsMu.Lock()
	defer a.addrsMu.Unlock()

	e, ok := a.addrs[instance]
	if !ok {
		return "", errAddrNotFound
	}

	now := time.Now()

	// delete the address if it's expired. This will trigger at the end our
	// kubeclient to make another lookup to get the Service address.
	if e.added.Add(expireTTL).Before(now) {
		delete(a.addrs, instance)
		return "", errAddrNotFound
	}

	return e.addr, nil
}
