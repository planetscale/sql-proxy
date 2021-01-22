package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/planetscale/sql-proxy/sigutil"
)

type server struct {
	cfg         *tls.Config
	localAddr   string
	backendAddr string
}

func main() {
	if err := realMain(); err != nil {
		log.Fatalln(err)
	}
}

func realMain() error {
	caPath := flag.String("ca", "testcerts/ca.pem", "MySQL CA Cert path")
	serverCertPath := flag.String("cert", "testcerts/server-cert.pem", "MySQL server Cert path")
	serverKeyPath := flag.String("key", "testcerts/server-key.pem", "MySQL server Key path")

	backendAddr := flag.String("backend-addr", "127.0.0.1:3306", "MySQL backend network address")
	localAddr := flag.String("local-addr", "127.0.0.1:3308", "Local address to bind and listen")

	flag.Parse()

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

	srv := &server{
		cfg:         cfg,
		localAddr:   *localAddr,
		backendAddr: *backendAddr,
	}

	log.Println("ready for new connections")
	return srv.Run(ctx)
}

// Run runs the server proxy
func (s *server) Run(ctx context.Context) error {
	log.Printf("listening on %s", s.localAddr)
	l, err := net.Listen("tcp", s.localAddr)
	if err != nil {
		return err
	}
	return s.run(ctx, l)
}

// run runs the server proxy. This is an unexported function to make testing
// usable.
func (s *server) run(ctx context.Context, l net.Listener) error {
	for {
		select {
		case <-ctx.Done():
			termTimeout := time.Second * 1
			log.Printf("received context cancellation. Waiting up to %s before terminating.", termTimeout)
			return nil
		default:
			c, err := l.Accept()
			if err != nil {
				return err
			}
			defer l.Close()

			go func() {
				if err := s.handleConn(ctx, c); err != nil {
					log.Printf("error proxying conn: %s", err)
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
		return err
	}

	cn := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
	log.Printf("new connection for %q with CN: %q", s.backendAddr, cn)

	st := strings.Split(cn, "/")
	if len(st) != 3 {
		return fmt.Errorf("CN instance format is malformed, should be in form organization/dbname/branch, have: %q", cn)
	}

	// TODO(fatih): do the routing based on CN
	org, db, branch := st[0], st[1], st[2]
	log.Printf("CN verified: %s/%s/%s\n", org, db, branch)

	var d net.Dialer
	backendConn, err := d.DialContext(ctx, "tcp", s.backendAddr) // mysql instance
	if err != nil {
		return fmt.Errorf("couldn't connect to backend: %s", err)
	}

	copyThenClose(backendConn, tlsConn, "remote conn", "local conn on "+s.backendAddr)
	return nil
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
	log.Printf("%v had error: %v", desc, err)
}
