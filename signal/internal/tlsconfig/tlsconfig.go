package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Load returns a *tls.Config and a boolean indicating whether a self-signed
// certificate was generated (true) or a user-provided cert was loaded (false).
//
// If certFile and keyFile are both non-empty the cert is loaded from disk.
// Otherwise a self-signed ECDSA P-256 certificate is used: persisted to
// persistDir and reused across restarts so the TOFU fingerprint stays stable.
// If persistDir is empty the self-signed cert is ephemeral (in-memory).
func Load(certFile, keyFile, persistDir string) (*tls.Config, bool, error) {
	var cert tls.Certificate
	var err error
	selfSigned := false

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, false, fmt.Errorf("loading TLS cert/key: %w", err)
		}
	} else {
		cert, err = loadOrCreateSelfSigned(persistDir)
		if err != nil {
			return nil, false, fmt.Errorf("self-signed cert: %w", err)
		}
		selfSigned = true
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Include h2 so both gRPC (HTTP/2) and plain HTTPS clients work.
		NextProtos: []string{"h2", "http/1.1"},
	}
	return cfg, selfSigned, nil
}

// loadOrCreateSelfSigned reuses a persisted self-signed cert from persistDir,
// generating and saving one on first run. With an empty dir it falls back to an
// ephemeral in-memory cert (which changes every restart — TOFU re-pin needed).
func loadOrCreateSelfSigned(dir string) (tls.Certificate, error) {
	if dir == "" {
		return generateSelfSigned()
	}
	crtPath := filepath.Join(dir, "self-signed.crt")
	keyPath := filepath.Join(dir, "self-signed.key")

	if cert, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
		return cert, nil
	}

	certPEM, keyPEM, err := generateSelfSignedPEM()
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		// Can't persist — fall back to the in-memory cert we just generated.
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	_ = os.WriteFile(crtPath, certPEM, 0o600)
	_ = os.WriteFile(keyPath, keyPEM, 0o600)
	return tls.X509KeyPair(certPEM, keyPEM)
}

func generateSelfSigned() (tls.Certificate, error) {
	certPEM, keyPEM, err := generateSelfSignedPEM()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func generateSelfSignedPEM() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	hostname, _ := os.Hostname()

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Bline-X"},
			CommonName:   hostname,
		},
		DNSNames:              []string{"localhost", hostname},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
