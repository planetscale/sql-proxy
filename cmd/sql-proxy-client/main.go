package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	ps "github.com/planetscale/planetscale-go/planetscale"
	"github.com/planetscale/sql-proxy/proxy"
	"github.com/planetscale/sql-proxy/sigutil"
)

var (
	version string
	commit  string
	date    string
)

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func realMain() error {
	localAddr := flag.String("local-addr", "127.0.0.1:3307",
		"Local address to bind and listen for connections")
	remoteAddr := flag.String("remote-addr", "",
		"MySQL remote network address")
	remotePort := flag.Int("remote-port", 3307, "MySQL remote port")
	instance := flag.String("instance", "",
		"The PlanetScale Database instance in the form of organization/database/branch")
	token := flag.String("token", "", "The PlanetScale API token")
	showVersion := flag.Bool("version", false, "Show version of the proxy")

	caPath := flag.String("ca", "", "MySQL CA Cert path")
	clientCertPath := flag.String("cert", "", "MySQL Client Cert path")
	clientKeyPath := flag.String("key", "", "MySQL Client Key path")

	flag.Parse()

	if *showVersion {
		printVersion(version, commit, date)
		return nil
	}

	if *token == "" {
		return errors.New("--token is not set. Please provide a PlanetScale API token")
	}

	if *instance == "" {
		return errors.New("--instance is not set. Please provide the PlanetScale DB instance in the form of organization/database/branch")
	}

	var certSource proxy.CertSource
	var err error

	certSource, err = newRemoteCertSource(*token)
	if err != nil {
		return err
	}

	if *caPath != "" && *clientCertPath != "" && *clientKeyPath != "" {
		certSource, err = newLocalCertSource(*caPath, *clientCertPath, *clientKeyPath, *remoteAddr, *remotePort)
		if err != nil {
			return err
		}
	}

	p, err := proxy.NewClient(proxy.Options{
		CertSource: certSource,
		LocalAddr:  *localAddr,
		RemoteAddr: *remoteAddr,
		Instance:   *instance,
	})
	if err != nil {
		return fmt.Errorf("couldn't create proxy client: %s", err)
	}

	// TODO(fatih): replace with signal.NotifyContext once Go 1.16 is released
	// https://go-review.googlesource.com/c/go/+/219640
	ctx := sigutil.WithSignal(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	return p.Run(ctx)
}

type remoteCertSource struct {
	client *ps.Client
}

func newRemoteCertSource(token string) (*remoteCertSource, error) {
	client, err := ps.NewClient(
		ps.WithAccessToken(token),
	)
	if err != nil {
		return nil, err
	}

	return &remoteCertSource{
		client: client,
	}, nil
}

func (r *remoteCertSource) Cert(ctx context.Context, org, db, branch string) (*proxy.Cert, error) {
	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate private key: %s", err)
	}

	cert, err := r.client.Certificates.Create(ctx, &ps.CreateCertificateRequest{
		Organization: org,
		DatabaseName: db,
		Branch:       branch,
		PrivateKey:   pkey,
	})
	if err != nil {
		return nil, err
	}

	return &proxy.Cert{
		ClientCert: cert.ClientCert,
		CACert:     cert.CACert,
		RemoteAddr: cert.RemoteAddr,
	}, nil
}

func newLocalCertSource(caPath, certPath, keyPath, remoteAddr string, remotePort int) (*localCertSource, error) {
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
		remoteAddr: remoteAddr,
		remotePort: remotePort,
	}, nil

}

type localCertSource struct {
	cert       tls.Certificate
	caCert     *x509.Certificate
	remoteAddr string
	remotePort int
}

func (c *localCertSource) Cert(ctx context.Context, org, db, branch string) (*proxy.Cert, error) {
	return &proxy.Cert{
		ClientCert: c.cert,
		CACert:     c.caCert,
		RemoteAddr: c.remoteAddr,
		Ports: proxy.RemotePorts{
			Proxy: c.remotePort,
		},
	}, nil
}

func parseCert(pemCert []byte) (*x509.Certificate, error) {
	bl, _ := pem.Decode(pemCert)
	if bl == nil {
		return nil, errors.New("invalid PEM: " + string(pemCert))
	}
	return x509.ParseCertificate(bl.Bytes)
}

// printVersion formats a version string with the given information.
func printVersion(ver, commit, buildDate string) {
	if ver == "" && buildDate == "" && commit == "" {
		fmt.Print("pscale version (built from source)")
	}

	ver = strings.TrimPrefix(ver, "v")

	fmt.Printf("pscale version %s (build date: %s commit: %s)\n", ver, buildDate, commit)
}
