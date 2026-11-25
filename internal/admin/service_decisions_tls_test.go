package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
)

func decisionClientCertificate(t *testing.T, cn string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-router-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	must(t, err)
	root, err := x509.ParseCertificate(caDER)
	must(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, public, key)
	must(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}, pool
}

func TestServiceDecisionNativeGatewayTLS(t *testing.T) {
	_, _, mux := decisionSetup(t)
	cert, pool := decisionClientCertificate(t, "gateway")
	stack := gatewayctx.TrustedMiddleware(func(r *http.Request) error {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			return fmt.Errorf("verified gateway required")
		}
		return nil
	})(mux)
	server := httptest.NewUnstartedServer(stack)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	client.Transport = transport
	send := func() (int, error) {
		r, err := http.NewRequest("POST", server.URL+"/svc/decisions/check", strings.NewReader(decisionBody("background")))
		if err != nil {
			return 0, err
		}
		id := decisionIdentity("svc:worker")
		r.Header.Set(gatewayctx.HeaderSubject, id.Subject)
		if err = gatewayctx.SetCaller(r.Header, id.Caller); err != nil {
			return 0, err
		}
		resp, err := client.Do(r)
		if err != nil {
			return 0, err
		}
		defer func() { must(t, resp.Body.Close()) }()
		return resp.StatusCode, nil
	}
	status, err := send()
	must(t, err)
	if status != 200 {
		t.Fatal("valid gateway TLS rejected", status)
	}
	// A leaf with the configured CN under another CA cannot establish ingress.
	other, _ := decisionClientCertificate(t, "gateway")
	transport.CloseIdleConnections()
	transport.TLSClientConfig.Certificates = []tls.Certificate{other}
	if status, err = send(); err == nil && status == 200 {
		t.Fatal("foreign CA accepted")
	}
}
