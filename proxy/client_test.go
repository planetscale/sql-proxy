package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
	"unsafe"

	qt "github.com/frankban/quicktest"
	"go.uber.org/zap/zaptest"
)

const (
	textFixtures = "./testcerts"
)

func TestClient_Run_Cancellation(t *testing.T) {
	c := qt.New(t)
	client, err := NewClient(testOptions(t))
	c.Assert(err, qt.IsNil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan bool)
	go func() {
		client.Run(ctx)
		close(done)
	}()

	cancel()
	<-done
}

func TestClient_clientCerts(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	clientCert := tls.Certificate{}
	remoteAddr := "branchid.turtle.example.com"
	wantRemoteAddr := "branchid.turtle.example.com:3306"
	org, db, branch := "myorg", "mydb", "mybranch"
	instance := fmt.Sprintf("%s/%s/%s", org, db, branch)

	certSource := &fakeCertSource{
		CertFn: func(ctx context.Context, o, d, b string) (*Cert, error) {
			c.Check(o, qt.Equals, org)
			c.Check(d, qt.Equals, db)
			c.Check(b, qt.Equals, branch)
			return &Cert{
				ClientCert: clientCert,
				AccessHost: remoteAddr,
				Ports: RemotePorts{
					Proxy: 3306,
				},
			}, nil
		},
	}

	testOpts := testOptions(t)
	testOpts.CertSource = certSource
	client, err := NewClient(testOpts)
	c.Assert(err, qt.IsNil)

	cert, addr, err := client.clientCerts(ctx, instance)
	c.Assert(err, qt.IsNil)
	c.Assert(certSource.CertFnInvoked, qt.IsTrue)
	c.Assert(cert.Certificates, qt.HasLen, 1)
	c.Assert(cert.Certificates[0], qt.DeepEquals, clientCert)
	c.Assert(addr, qt.Equals, wantRemoteAddr)
}

func TestClient_clientCerts_has_cache(t *testing.T) {
	c := qt.New(t)
	ctx := context.Background()

	org, db, branch := "myorg", "mydb", "mybranch"
	instance := fmt.Sprintf("%s/%s/%s", org, db, branch)

	certSource := &fakeCertSource{
		CertFn: func(ctx context.Context, o, d, b string) (*Cert, error) {
			return &Cert{}, nil
		},
	}

	testOpts := testOptions(t)
	client, err := NewClient(testOpts)
	c.Assert(err, qt.IsNil)

	cfg := &tls.Config{ServerName: "server", MinVersion: tls.VersionTLS12}
	remoteAddr := "foo.example.com"
	client.configCache.Add(instance, cfg, remoteAddr)

	cert, addr, err := client.clientCerts(ctx, instance)
	c.Assert(err, qt.IsNil)
	c.Assert(certSource.CertFnInvoked, qt.IsFalse)
	c.Assert(cert.ServerName, qt.Equals, cfg.ServerName)
	c.Assert(addr, qt.Equals, remoteAddr)
}

func TestClient_SyncAtomicAlignment(t *testing.T) {
	c := qt.New(t)

	// copied from: https://github.com/GoogleCloudPlatform/cloudsql-proxy/blob/302d5d87ac52d8b814625f7b27344fd9ba6a0348/proxy/proxy/client_test.go#L290
	// The sync/atomic pkg has a bug that requires the developer to guarantee
	// 64-bit alignment when using 64-bit functions on 32-bit systems.
	client := &Client{} //lint:ignore SA4006 it's used below
	offset := unsafe.Offsetof(client.connectionsCounter)
	c.Assert(int(offset%64), qt.Equals, 0, qt.Commentf("Client.connectionsCounter is not aligned"))
}

type testCert struct {
	serverCfg  *tls.Config
	clientCert tls.Certificate
}

func testCerts(t testing.TB) testCert {
	c := qt.New(t)
	c.Helper()

	caBuf, err := ioutil.ReadFile(filepath.Join(textFixtures, "ca.crt"))
	c.Assert(err, qt.IsNil)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caBuf)

	serverCerts, err := tls.LoadX509KeyPair(
		filepath.Join(textFixtures, "server.crt"),
		filepath.Join(textFixtures, "server.key"),
	)
	c.Assert(err, qt.IsNil)

	clientCerts, err := tls.LoadX509KeyPair(
		filepath.Join(textFixtures, "client.crt"),
		filepath.Join(textFixtures, "client.key"),
	)
	c.Assert(err, qt.IsNil)

	serverCfg := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		ClientCAs:                caPool,
		Certificates:             []tls.Certificate{serverCerts},
	}

	return testCert{
		serverCfg:  serverCfg,
		clientCert: clientCerts,
	}
}

func testOptions(t *testing.T) Options {
	return Options{
		Logger: zaptest.NewLogger(t),
	}
}

type fakeCertSource struct {
	CertFn        func(ctx context.Context, org, db, branch string) (*Cert, error)
	CertFnInvoked bool
}

func (f *fakeCertSource) Cert(ctx context.Context, org, db, branch string) (*Cert, error) {
	f.CertFnInvoked = true

	return f.CertFn(ctx, org, db, branch)

}

func parseCert(pemCert []byte) (*x509.Certificate, error) {
	bl, _ := pem.Decode(pemCert)
	if bl == nil {
		return nil, errors.New("invalid PEM: " + string(pemCert))
	}
	return x509.ParseCertificate(bl.Bytes)
}
