package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"
)

// CABundle holds a self-signed CA certificate and its private key.
type CABundle struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// WorkloadCert holds a workload's signed certificate.
type WorkloadCert struct {
	Cert    *x509.Certificate
	CertPEM []byte
}

// CertOptions provides optional SAN fields when issuing agent certificates.
type CertOptions struct {
	DNSNames    []string
	IPAddresses []net.IP
}

// GenerateCA creates a self-signed EC P-256 CA for the given trust domain.
func GenerateCA(trustDomain string) (*CABundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "WIMSE CA – " + trustDomain},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return &CABundle{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

// IssueAgentCert signs a certificate for an agent identified by the given URI SAN.
// The URI is typically a SPIFFE ID (spiffe://trust-domain/agent/name) or
// WIMSE workload ID (wimse://trust-domain/agent/name).
// The same EC key pair should be used for the mTLS cert AND the AgentToken cnf.jwk,
// binding transport identity to application identity.
func (ca *CABundle) IssueAgentCert(uri string, pub *ecdsa.PublicKey, opts *CertOptions) (*WorkloadCert, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil || parsedURI.Scheme == "" {
		return nil, errors.New("uri must be an absolute URI")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: uri},
		URIs:         []*url.URL{parsedURI},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if opts != nil {
		tmpl.DNSNames = opts.DNSNames
		tmpl.IPAddresses = opts.IPAddresses
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create agent cert: %w", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return &WorkloadCert{Cert: cert, CertPEM: certPEM}, nil
}

// CertPool returns an x509.CertPool containing only this CA's certificate.
func (ca *CABundle) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// TLSCertificate builds a tls.Certificate from a WorkloadCert and its private key.
func TLSCertificate(wc *WorkloadCert, priv *ecdsa.PrivateKey) (tls.Certificate, error) {
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(wc.CertPEM, keyPEM)
}

// NewServerTLSConfig builds a TLS 1.3 server config requiring mutual client certificates.
// clientCA is the CA pool that issued agent client certificates.
func NewServerTLSConfig(clientCA *x509.CertPool, wc *WorkloadCert, priv *ecdsa.PrivateKey) (*tls.Config, error) {
	cert, err := TLSCertificate(wc, priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// NewClientTLSConfig builds a TLS 1.3 client config presenting a client certificate.
// serverCA is the CA pool that issued the gateway server certificate.
func NewClientTLSConfig(serverCA *x509.CertPool, wc *WorkloadCert, priv *ecdsa.PrivateKey) (*tls.Config, error) {
	cert, err := TLSCertificate(wc, priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      serverCA,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// SaveCABundle writes the CA certificate PEM and private key PEM to separate files.
// The key file is created with mode 0600.
func SaveCABundle(ca *CABundle, certPath, keyPath string) error {
	if err := os.WriteFile(certPath, ca.CertPEM, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(keyPath, keyPEM, 0600)
}

// LoadCABundle reads a CA certificate and EC private key from PEM files.
func LoadCABundle(certPath, keyPath string) (*CABundle, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block in CA cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, errors.New("no EC PRIVATE KEY block in CA key file")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CABundle{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

// LoadCACertPool reads a CA certificate PEM file and returns a CertPool containing it.
func LoadCACertPool(certPath string) (*x509.CertPool, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("no valid certificates found in CA cert file")
	}
	return pool, nil
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	return n, nil
}
