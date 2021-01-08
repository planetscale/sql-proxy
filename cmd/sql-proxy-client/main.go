package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	keepAlivePeriod = time.Minute
)

func main() {
	if err := realMain(); err != nil {
		log.Fatalln(err)
	}
}

func realMain() error {
	remoteAddr := flag.String("remote-addr", "127.0.0.1:3308", "MySQL remote network address")
	dbname := flag.String("db", "", "MySQL Database name")

	caPath := flag.String("ca", "testcerts/ca.pem", "MySQL CA Cert path")
	clientCertPath := flag.String("cert", "testcerts/client-cert.pem", "MySQL Client Cert path")
	clientKeyPath := flag.String("key", "testcerts/client-key.pem", "MySQL Client Key path")

	flag.Parse()

	certSource, err := newLocalCertSource(*remoteAddr, *dbname, *caPath, *clientCertPath, *clientKeyPath)
	if err != nil {
		return err
	}

	p := &proxyClient{
		MaxConnections: 0, // no limit
		Certs:          certSource,
	}

	addr := "127.0.0.1:3307"
	connSrc := make(chan proxyConn, 1)
	go func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("error net.Listen: %s", err)
			return
		}
		log.Printf("listening on %s for %s", addr, *dbname)

		for {
			start := time.Now()
			c, err := l.Accept()
			if err != nil {
				log.Printf("error in accept for on %v: %v", addr, err)
				if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
					d := 10*time.Millisecond - time.Since(start)
					if d > 0 {
						time.Sleep(d)
					}
					continue
				}
				l.Close()
				return
			}

			log.Printf("new connection for %q", addr)

			switch clientConn := c.(type) {
			case *net.TCPConn:
				clientConn.SetKeepAlive(true)
				clientConn.SetKeepAlivePeriod(1 * time.Minute)
			}

			connSrc <- proxyConn{
				Conn:     c,
				Instance: *dbname, // TODO(fatih): fix this
			}
		}
	}()

	// TODO(fatih): replace with signal.NotifyContext once Go 1.16 is released
	// https://go-review.googlesource.com/c/go/+/219640
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	termTimeout := time.Second * 1
	go func() {
		<-signals
		log.Printf("received TERM signal. Waiting up to %s before terminating.", termTimeout)

		err := p.Shutdown(termTimeout)
		if err == nil {
			os.Exit(0)
		}
		log.Printf("error during SIGTERM shutdown: %v", err)
		os.Exit(2)
	}()

	log.Println("ready for new connections")

	for conn := range connSrc {
		go func() {
			err := p.handleConn(context.Background(), conn.Conn, conn.Instance)
			if err != nil {
				log.Printf("error proxying conn: %s", err)
			}
		}()
	}

	return nil
}

type proxyClient struct {
	// MaxConnections is the maximum number of connections to establish
	// before refusing new connections. 0 means no limit.
	MaxConnections uint64

	// Required; specifies how certificates are obtained.
	Certs CertSource

	// connectionsCounter is used to enforce the optional maxConnections limit
	connectionsCounter uint64
}

// proxyConn represents a connection from a client to a specific instance.
type proxyConn struct {
	Instance string
	Conn     net.Conn
}

func (p *proxyClient) handleConn(ctx context.Context, conn net.Conn, instance string) error {
	active := atomic.AddUint64(&p.connectionsCounter, 1)

	// Deferred decrement of ConnectionsCounter upon connection closing
	defer atomic.AddUint64(&p.connectionsCounter, ^uint64(0))

	if p.MaxConnections > 0 && active > p.MaxConnections {
		conn.Close()
		return fmt.Errorf("too many open connections (max %d)", p.MaxConnections)
	}

	// TODO(fatih): cache certs
	mycert, err := p.Certs.Local(instance)
	if err != nil {
		return fmt.Errorf("couldn't retrieve certs for local connection: %s", err)
	}

	scert, remoteAddr, name, err := p.Certs.Remote(instance)
	if err != nil {
		return fmt.Errorf("couldn't retrieve certs for remote connection: %s", err)
	}
	certs := x509.NewCertPool()
	certs.AddCert(scert)

	cfg := &tls.Config{
		ServerName:   name,
		Certificates: []tls.Certificate{mycert},
		RootCAs:      certs,
		// We need to set InsecureSkipVerify to true due to
		// https://github.com/GoogleCloudPlatform/cloudsql-proxy/issues/194
		// https://tip.golang.org/doc/go1.11#crypto/x509
		//
		// Since we have a secure channel to the Cloud SQL API which we use to retrieve the
		// certificates, we instead need to implement our own VerifyPeerCertificate function
		// that will verify that the certificate is OK.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: genVerifyPeerCertificateFunc(name, certs),
	}

	// TODO(fatih): implement refreshing certs
	// go p.refreshCertAfter(instance, timeToRefresh)

	var d net.Dialer
	remoteConn, err := d.DialContext(ctx, "tcp", remoteAddr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("couldn't connect to %q: %v", remoteAddr, err)
	}

	type setKeepAliver interface {
		SetKeepAlive(keepalive bool) error
		SetKeepAlivePeriod(d time.Duration) error
	}

	if s, ok := conn.(setKeepAliver); ok {
		if err := s.SetKeepAlive(true); err != nil {
			log.Printf("Couldn't set KeepAlive to true: %v", err)
		} else if err := s.SetKeepAlivePeriod(keepAlivePeriod); err != nil {
			fmt.Println("true 2")
			log.Printf("Couldn't set KeepAlivePeriod to %v", keepAlivePeriod)
		}
	} else {
		log.Printf("KeepAlive not supported: long-running tcp connections may be killed by the OS.")
	}

	secureConn := tls.Client(remoteConn, cfg)
	if err := secureConn.Handshake(); err != nil {
		secureConn.Close()
		return fmt.Errorf("couldn't initiate TLS handshake to remote addr: %s", err)
	}

	// Hasta la vista, baby
	copyThenClose(
		secureConn,
		conn,
		"remote connection",
		"local connection on "+conn.LocalAddr().String(),
	)
	return nil
}

// Shutdown waits up to a given amount of time for all active connections to
// close. Returns an error if there are still active connections after waiting
// for the whole length of the timeout.
func (p *proxyClient) Shutdown(termTimeout time.Duration) error {
	term, ticker := time.After(termTimeout), time.NewTicker(100*time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if atomic.LoadUint64(&p.connectionsCounter) > 0 {
				continue
			}
		case <-term:
		}
		break
	}

	active := atomic.LoadUint64(&p.connectionsCounter)
	if active == 0 {
		return nil
	}
	return fmt.Errorf("%d active connections still exist after waiting for %v", active, termTimeout)
}

func newLocalCertSource(remoteAddr, dbname, caPath, certPath, keyPath string) (*localCertSource, error) {
	pem, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	caCert, err := parseCert(pem)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cert.Leaf = caCert

	return &localCertSource{
		cert:       cert,
		caCert:     caCert,
		name:       "MySQL_Server_5.7.32_Auto_Generated_Server_Certificate",
		remoteAddr: remoteAddr,
	}, nil

}

type localCertSource struct {
	cert   tls.Certificate
	caCert *x509.Certificate

	name       string
	remoteAddr string
}

func (c *localCertSource) Local(instance string) (tls.Certificate, error) {
	return c.cert, nil
}

func (c *localCertSource) Remote(instance string) (cert *x509.Certificate, remoteAddr, name string, err error) {
	return c.caCert, c.remoteAddr, c.name, nil
}

func parseCert(pemCert []byte) (*x509.Certificate, error) {
	bl, _ := pem.Decode(pemCert)
	if bl == nil {
		return nil, errors.New("invalid PEM: " + string(pemCert))
	}
	return x509.ParseCertificate(bl.Bytes)
}

func copyThenClose(remote, local io.ReadWriteCloser, remoteDesc, localDesc string) {
	firstErr := make(chan error, 1)

	go func() {
		readErr, err := myCopy(remote, local)
		select {
		case firstErr <- err:
			if readErr && err == io.EOF {
				log.Printf("client closed %v", localDesc)
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
			log.Printf("instance %v closed connection", remoteDesc)
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

func logError(readDesc, writeDesc string, readErr bool, err error) {
	var desc string
	if readErr {
		desc = "reading data from " + readDesc
	} else {
		desc = "writing data to " + writeDesc
	}
	log.Printf("%v had error: %v", desc, err)
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

// CertSource is how a Client obtains various certificates required for operation.
type CertSource interface {
	// Local returns a certificate that can be used to authenticate with the
	// provided instance.
	Local(instance string) (tls.Certificate, error)

	// Remote returns the instance's CA certificate, address, and name.
	Remote(instance string) (cert *x509.Certificate, remoteAddr, name string, err error)
}

// genVerifyPeerCertificateFunc creates a VerifyPeerCertificate func that verifies that the peer
// certificate is in the cert pool. We need to define our own because of our sketchy non-standard
// CNs.
func genVerifyPeerCertificateFunc(instanceName string, pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate to verify")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("x509.ParseCertificate(rawCerts[0]) returned error: %v", err)
		}

		opts := x509.VerifyOptions{Roots: pool}
		if _, err = cert.Verify(opts); err != nil {
			return err
		}

		if cert.Subject.CommonName != instanceName {
			return fmt.Errorf("certificate had CN %q, expected %q", cert.Subject.CommonName, instanceName)
		}
		return nil
	}
}
