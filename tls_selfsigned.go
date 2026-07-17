// Package main
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const selfSignedCertificateLifetime = 365 * 24 * time.Hour

// ============================================================================
// TLS FILE
// resolveDashboardTLSFiles returns an explicitly configured certificate pair,
// or creates/reuses a persistent self-signed pair under CONFIG_DIR/tls.
// ============================================================================
func resolveDashboardTLSFiles() (certFile, keyFile string, selfSigned bool, err error) {
	certFile = strings.TrimSpace(os.Getenv("DASHBOARD_TLS_CERT"))
	keyFile = strings.TrimSpace(os.Getenv("DASHBOARD_TLS_KEY"))

	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return "", "", false, errors.New("DASHBOARD_TLS_CERT and DASHBOARD_TLS_KEY must both be set")
		}
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return "", "", false, fmt.Errorf("load configured TLS certificate: %w", err)
		}
		return certFile, keyFile, false, nil
	}

	tlsDir := filepath.Join(configDir, emailTLSModeTLS)
	certFile = filepath.Join(tlsDir, "dashboard.crt")
	keyFile = filepath.Join(tlsDir, "dashboard.key")

	dnsNames, ipAddresses := dashboardCertificateNames()
	if err := ensureSelfSignedCertificate(certFile, keyFile, dnsNames, ipAddresses); err != nil {
		return "", "", true, err
	}

	return certFile, keyFile, true, nil
}

func dashboardCertificateNames() ([]string, []net.IP) {
	dnsSet := map[string]struct{}{
		"localhost": {},
	}
	ipSet := map[string]net.IP{
		"127.0.0.1": net.ParseIP("127.0.0.1"),
		"::1":       net.ParseIP("::1"),
	}

	if hostname, err := os.Hostname(); err == nil {
		hostname = strings.TrimSpace(hostname)
		if hostname != "" {
			dnsSet[hostname] = struct{}{}
		}
	}

	addCertificateHost(getLocalIP(), dnsSet, ipSet)
	for host := range strings.SplitSeq(os.Getenv("DASHBOARD_TLS_HOSTS"), ",") {
		addCertificateHost(host, dnsSet, ipSet)
	}

	dnsNames := make([]string, 0, len(dnsSet))
	for name := range dnsSet {
		dnsNames = append(dnsNames, name)
	}
	sort.Strings(dnsNames)

	ipKeys := make([]string, 0, len(ipSet))
	for key := range ipSet {
		ipKeys = append(ipKeys, key)
	}
	sort.Strings(ipKeys)

	ipAddresses := make([]net.IP, 0, len(ipKeys))
	for _, key := range ipKeys {
		ipAddresses = append(ipAddresses, ipSet[key])
	}

	return dnsNames, ipAddresses
}

func addCertificateHost(raw string, dnsSet map[string]struct{}, ipSet map[string]net.IP) {
	host := strings.TrimSpace(raw)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = strings.Trim(parsedHost, "[]")
	}
	if host == "" {
		return
	}

	if parsed := net.ParseIP(host); parsed != nil {
		ipSet[parsed.String()] = parsed
		return
	}

	dnsSet[strings.ToLower(host)] = struct{}{}
}

func ensureSelfSignedCertificate(certFile, keyFile string, dnsNames []string, ipAddresses []net.IP) error {
	if certificatePairIsUsable(certFile, keyFile, dnsNames, ipAddresses) {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return fmt.Errorf("create TLS directory: %w", err)
	}
	if filepath.Dir(certFile) != filepath.Dir(keyFile) {
		if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
			return fmt.Errorf("create TLS key directory: %w", err)
		}
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate TLS private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate TLS certificate serial: %w", err)
	}
	if serialNumber.Sign() == 0 {
		serialNumber.SetInt64(1)
	}

	hostname, _ := os.Hostname()
	commonName := strings.TrimSpace(hostname)
	if commonName == "" {
		commonName = "Go Dashboard"
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Go Dashboard (self-signed)"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(selfSignedCertificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return fmt.Errorf("create self-signed TLS certificate: %w", err)
	}

	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)

	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	if err := writeTLSFile(certFile, certificatePEM, 0o644); err != nil {
		return fmt.Errorf("write TLS certificate: %w", err)
	}
	if err := writeTLSFile(keyFile, privateKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write TLS private key: %w", err)
	}

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("verify generated TLS certificate: %w", err)
	}
	return nil
}

func certificatePairIsUsable(certFile, keyFile string, dnsNames []string, ipAddresses []net.IP) bool {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}

	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}

	now := time.Now()
	if now.Before(certificate.NotBefore) || certificate.NotAfter.Before(now.Add(30*24*time.Hour)) {
		return false
	}

	for _, dnsName := range dnsNames {
		if err := certificate.VerifyHostname(dnsName); err != nil {
			return false
		}
	}
	for _, ipAddress := range ipAddresses {
		if err := certificate.VerifyHostname(ipAddress.String()); err != nil {
			return false
		}
	}

	return true
}

func writeTLSFile(path string, data []byte, mode os.FileMode) error {
	temporaryFile, err := os.CreateTemp(filepath.Dir(path), ".tls-*")
	if err != nil {
		return err
	}
	temporaryPath := temporaryFile.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if err := temporaryFile.Chmod(mode); err != nil {
		_ = temporaryFile.Close()
		return err
	}
	if _, err := temporaryFile.Write(data); err != nil {
		_ = temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Sync(); err != nil {
		_ = temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Close(); err != nil {
		return err
	}

	return os.Rename(temporaryPath, path)
}
