package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GoogleCloudPlatform/cloudsql-proxy/logging"
	"github.com/GoogleCloudPlatform/cloudsql-proxy/proxy/proxy"
)

func main() {
	if err := realMain(); err != nil {
		log.Fatalln(err)
	}
}

func realMain() error {
	// user := flag.String("user", "root", "MySQL user")
	// password := flag.String("password", "", "MySQL password")
	remoteAddr := flag.String("remote-addr", "127.0.0.1", "MySQL network address")
	dbname := flag.String("db", "", "MySQL Database name")

	caPath := flag.String("ca", "testcerts/ca.pem", "MySQL CA Cert path")
	clientCertPath := flag.String("cert", "testcerts/client-cert.pem", "MySQL Client Cert path")
	clientKeyPath := flag.String("key", "testcerts/client-key.pem", "MySQL Client Key path")

	flag.Parse()

	certSource, err := newLocalCertSource(*remoteAddr, *dbname, *caPath, *clientCertPath, *clientKeyPath)
	if err != nil {
		return err
	}

	var d net.Dialer

	proxyClient := &proxy.Client{
		Port:           3308, // remote DB port
		MaxConnections: 0,    // no limit
		Conns:          proxy.NewConnSet(),
		Certs:          certSource,
		ContextDialer:  d.DialContext,
	}

	addr := "127.0.0.1:3307"
	connSrc := make(chan proxy.Conn, 1)
	go func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Println("error net.Listen: %s", err)
			return
		}

		go func() {
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
				connSrc <- proxy.Conn{*dbname, c}
			}
		}()

		logging.Infof("listening on %s for %s", addr, *dbname)

	}()

	// TODO(fatih): replace with signal.NotifyContext once Go 1.16 is released
	// https://go-review.googlesource.com/c/go/+/219640
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	termTimeout := time.Second * 1
	go func() {
		<-signals
		log.Printf("Received TERM signal. Waiting up to %s before terminating.", termTimeout)

		err := proxyClient.Shutdown(termTimeout)
		if err == nil {
			os.Exit(0)
		}
		log.Printf("Error during SIGTERM shutdown: %v", err)
		os.Exit(2)
	}()

	log.Println("Ready for new connections")

	proxyClient.Run(connSrc)
	return nil
}

func newLocalCertSource(addr, dbname, caPath, certPath, keyPath string) (*localCertSource, error) {
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
		cert:   cert,
		caCert: caCert,
		name:   "MySQL_Server_5.7.32_Auto_Generated_Server_Certificate",
		addr:   addr,
	}, nil

}

type localCertSource struct {
	cert   tls.Certificate
	caCert *x509.Certificate

	name string
	addr string
}

func (c *localCertSource) Local(instance string) (tls.Certificate, error) {
	return c.cert, nil
}

func (c *localCertSource) Remote(instance string) (cert *x509.Certificate, addr, name, version string, err error) {
	return c.caCert, c.addr, c.name, "", nil
}

func parseCert(pemCert []byte) (*x509.Certificate, error) {
	bl, _ := pem.Decode(pemCert)
	if bl == nil {
		return nil, errors.New("invalid PEM: " + string(pemCert))
	}
	return x509.ParseCertificate(bl.Bytes)
}
