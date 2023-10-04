package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	nanoid "github.com/matoous/go-nanoid/v2"

	ps "github.com/planetscale/planetscale-go/planetscale"

	"github.com/planetscale/sql-proxy/proxy"
)

var (
	version string
	commit  string
	date    string
)

const PublicIdAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
const PublicIdLength = 6

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func realMain() error {
	host := flag.String("host", os.Getenv("PLANETSCALE_LISTENING_HOST"), "Local host to bind and listen for connections")
	port := flag.String("port", "3306", "Local port to bind and listen for connections")

	remoteHost := flag.String("remote-host", "", "MySQL remote host")
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

	var certSource proxy.CertSource
	var err error
	var instance string

	if *token != "" || (*serviceToken != "" && *serviceTokenName != "") {
		if *orgName == "" || *dbName == "" || *branchName == "" {
			return errors.New("--org, --database or --branch is not set with a token")
		}
		instance = fmt.Sprintf("%s/%s/%s", *orgName, *dbName, *branchName)

		certSource, err = newRemoteCertSource(*token, *serviceToken, *serviceTokenName)
		if err != nil {
			return err
		}
	}

	if *remoteHost != "" && *clientCertPath != "" && *clientKeyPath != "" {
		localCertSource, err := newLocalCertSource(*clientCertPath, *clientKeyPath, *remoteHost, *remotePort)
		if err != nil {
			return err
		}
		certSource = localCertSource
		cert, err := x509.ParseCertificate(localCertSource.cert.Certificate[0])
		if err != nil {
			return err
		}
		instance = cert.Subject.String()
	}

	if certSource == nil {
		return errors.New("no configuration found, need either a token and org / datbase / branch parameters or separate specified certificate source and remote host")
	}

	p, err := proxy.NewClient(proxy.Options{
		CertSource: certSource,
		LocalAddr:  net.JoinHostPort(*host, *port),
		RemoteAddr: net.JoinHostPort(*remoteHost, strconv.Itoa(*remotePort)),
		Instance:   instance,
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

	request := &ps.DatabaseBranchCertificateRequest{
		Organization: org,
		Database:     db,
		Branch:       branch,
		DisplayName:  fmt.Sprintf("sql-proxy-%s-%s", time.Now().Format("2006-01-02"), nanoid.MustGenerate(PublicIdAlphabet, PublicIdLength)),
		PrivateKey:   pkey,
	}

	cert, err := r.client.Certificates.Create(ctx, request)
	if err != nil {
		return nil, err
	}

	keyPair, err := cert.X509KeyPair(request)
	if err != nil {
		return nil, err
	}

	return &proxy.Cert{
		ClientCert: keyPair,
		AccessHost: cert.Branch.AccessHostURL,
		Ports: proxy.RemotePorts{
			MySQL: 3306,
			Proxy: 3307,
		},
	}, nil
}

func newLocalCertSource(certPath, keyPath, remoteAddr string, remotePort int) (*localCertSource, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &localCertSource{
		cert:       cert,
		remoteAddr: remoteAddr,
		remotePort: remotePort,
	}, nil

}

type localCertSource struct {
	cert       tls.Certificate
	remoteAddr string
	remotePort int
}

func (c *localCertSource) Cert(ctx context.Context, org, db, branch string) (*proxy.Cert, error) {
	return &proxy.Cert{
		ClientCert: c.cert,
		AccessHost: c.remoteAddr,
		Ports: proxy.RemotePorts{
			Proxy: c.remotePort,
		},
	}, nil
}

// printVersion formats a version string with the given information.
func printVersion(ver, commit, buildDate string) {
	if ver == "" && buildDate == "" && commit == "" {
		fmt.Print("pscale version (built from source)")
	}

	ver = strings.TrimPrefix(ver, "v")

	fmt.Printf("pscale version %s (build date: %s commit: %s)\n", ver, buildDate, commit)
}
