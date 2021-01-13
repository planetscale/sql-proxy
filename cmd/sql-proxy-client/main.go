package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/planetscale/sql-proxy/proxy"
)

func main() {
	if err := realMain(); err != nil {
		log.Fatalln(err)
	}
}

func realMain() error {
	localAddr := flag.String("local-addr", "127.0.0.1:3307", "Local address to bind and listen for connections")
	remoteAddr := flag.String("remote-addr", "127.0.0.1:3308", "MySQL remote network address")
	dbname := flag.String("db", "testdb", "MySQL Database name")

	caPath := flag.String("ca", "testcerts/ca.pem", "MySQL CA Cert path")
	clientCertPath := flag.String("cert", "testcerts/client-cert.pem", "MySQL Client Cert path")
	clientKeyPath := flag.String("key", "testcerts/client-key.pem", "MySQL Client Key path")

	flag.Parse()

	certSource, err := newLocalCertSource(*caPath, *clientCertPath, *clientKeyPath)
	if err != nil {
		return err
	}

	p := &proxy.Client{
		CertSource: certSource,
		LocalAddr:  *localAddr,
		RemoteAddr: *remoteAddr,
		Instance:   *dbname,
	}

	// TODO(fatih): replace with signal.NotifyContext once Go 1.16 is released
	// https://go-review.googlesource.com/c/go/+/219640
	ctx := withSignal(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	log.Println("ready for new connections")
	return p.Run(ctx)
}

func newLocalCertSource(caPath, certPath, keyPath string) (*localCertSource, error) {
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
	}, nil

}

type localCertSource struct {
	cert   tls.Certificate
	caCert *x509.Certificate
}

func (c *localCertSource) Cert(ctx context.Context, db, branch string) (*proxy.Cert, error) {
	return &proxy.Cert{
		ClientCert: c.cert,
		CACert:     c.caCert,
	}, nil
}

func parseCert(pemCert []byte) (*x509.Certificate, error) {
	bl, _ := pem.Decode(pemCert)
	if bl == nil {
		return nil, errors.New("invalid PEM: " + string(pemCert))
	}
	return x509.ParseCertificate(bl.Bytes)
}

// withSignal returns a copy of the parent context with the context cancel
// function adjusted to be called when one of the given signals is received.
func withSignal(ctx context.Context, sig ...os.Signal) context.Context {
	c := make(chan os.Signal, 1)
	signal.Notify(c, sig...)
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		select {
		case <-ctx.Done():
		case <-c:
		}

		cancel()
		signal.Stop(c)
	}()

	return ctx
}
