package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"

	ps "github.com/planetscale/planetscale-go/planetscale"
	"github.com/planetscale/sql-proxy/proxy"
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
	host := flag.String("host", "127.0.0.1", "Local host to bind and listen for connections")
	port := flag.String("port", "3306", "Local port to bind and listen for connections")

	remoteAddr := flag.String("remote-addr", "", "MySQL remote network address")
	remotePort := flag.Int("remote-port", 3307, "MySQL remote port")

	orgName := flag.String("org", os.Getenv("PLANETSCALE_ORG"),
		"The PlanetScale Organization")
	dbName := flag.String("database", os.Getenv("PLANETSCALE_DATABASE"),
		"The PlanetScale Database")
	branchName := flag.String("branch", os.Getenv("PLANETSCALE_BRANCH"),
		"The PlanetScale Branch")

	token := flag.String("token", os.Getenv("PLANETSCALE_ACCESS_TOKEN"), "The PlanetScale API access token (PLANETSCALE_ACCESS_TOKEN)")
	serviceToken := flag.String("service-token", os.Getenv("PLANETSCALE_SERVICE_TOKEN"), "The PlanetScale API service token (PLANETSCALE_SERVICE_TOKEN)")
	serviceTokenName := flag.String("service-token-name", os.Getenv("PLANETSCALE_SERVICE_TOKEN_NAME"), "The PlanetScale API service token name (PLANETSCALE_SERVICE_TOKEN_NAME)")

	showVersion := flag.Bool("version", false, "Show version of the proxy")

	caPath := flag.String("ca", "", "MySQL CA Cert path")
	clientCertPath := flag.String("cert", "", "MySQL Client Cert path")
	clientKeyPath := flag.String("key", "", "MySQL Client Key path")

	flag.Parse()

	if *showVersion {
		printVersion(version, commit, date)
		return nil
	}

	if *token != "" && *serviceToken != "" && *serviceTokenName != "" {
		return errors.New("--token and --service-token/--service-token-name cannot be set at the same time")
	}

	if *orgName == "" || *dbName == "" || *branchName == "" {
		return errors.New("--org, --database or --branch is not set")
	}

	var certSource proxy.CertSource
	var err error

	certSource, err = newRemoteCertSource(*token, *serviceToken, *serviceTokenName)
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
		LocalAddr:  net.JoinHostPort(*host, *port),
		RemoteAddr: *remoteAddr,
		Instance:   fmt.Sprintf("%s/%s/%s", *orgName, *dbName, *branchName),
	})
	if err != nil {
		return fmt.Errorf("couldn't create proxy client: %s", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	return p.Run(ctx)
}

type remoteCertSource struct {
	client *ps.Client
}

func newRemoteCertSource(token, serviceToken, serviceTokenName string) (*remoteCertSource, error) {
	var opts []ps.ClientOption
	if token != "" {
		opts = append(opts, ps.WithAccessToken(token))
	} else {
		opts = append(opts, ps.WithServiceToken(serviceTokenName, serviceToken))
	}

	client, err := ps.NewClient(opts...)
	if err != nil {
		return nil, err
	}

	return &remoteCertSource{
		client: client,
	}, nil
}

func (r *remoteCertSource) Cert(ctx context.Context, org, db, branch string) (*proxy.Cert, error) {
	pkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		CACerts:    cert.CACerts,
		RemoteAddr: cert.RemoteAddr,
		Ports: proxy.RemotePorts{
			MySQL: cert.Ports.MySQL,
			Proxy: cert.Ports.Proxy,
		},
	}, nil
}

func newLocalCertSource(caPath, certPath, keyPath, remoteAddr string, remotePort int) (*localCertSource, error) {
	pem, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	caCerts, err := parseCaCerts(pem)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &localCertSource{
		cert:       cert,
		caCerts:    caCerts,
		remoteAddr: remoteAddr,
		remotePort: remotePort,
	}, nil

}

type localCertSource struct {
	cert       tls.Certificate
	caCerts    []*x509.Certificate
	remoteAddr string
	remotePort int
}

func (c *localCertSource) Cert(ctx context.Context, org, db, branch string) (*proxy.Cert, error) {
	return &proxy.Cert{
		ClientCert: c.cert,
		CACerts:    c.caCerts,
		RemoteAddr: c.remoteAddr,
		Ports: proxy.RemotePorts{
			Proxy: c.remotePort,
		},
	}, nil
}

func parseCaCerts(pemCert []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		var certBlock *pem.Block
		certBlock, pemCert = pem.Decode(pemCert)
		if certBlock == nil {
			break
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}
	return certs, nil
}

// printVersion formats a version string with the given information.
func printVersion(ver, commit, buildDate string) {
	if ver == "" && buildDate == "" && commit == "" {
		fmt.Print("pscale version (built from source)")
	}

	ver = strings.TrimPrefix(ver, "v")

	fmt.Printf("pscale version %s (build date: %s commit: %s)\n", ver, buildDate, commit)
}
