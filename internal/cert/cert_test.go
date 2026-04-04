package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

const (
	testCommonName = "example.com"
	testDNSName    = "www.example.com"
)

func TestParseX509CertificatesFromHandshakeMessage(t *testing.T) {
	derCertificate := generateTestCertificateDER(t)
	handshakeMessage := buildCertificateHandshakeMessage(derCertificate)

	certificates, err := ParseX509CertificatesFromHandshakeMessage(handshakeMessage)
	if err != nil {
		t.Fatalf("ParseX509CertificatesFromHandshakeMessage() failed: %v", err)
	}
	if len(certificates) != 1 {
		t.Fatalf("len(certificates) = %d, want 1", len(certificates))
	}
	if certificates[0].Subject.CommonName != testCommonName {
		t.Fatalf("CommonName = %q, want %q", certificates[0].Subject.CommonName, testCommonName)
	}
}

func TestParseX509CertificatesFromPEM(t *testing.T) {
	derCertificate := generateTestCertificateDER(t)
	pemCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCertificate})

	certificates, err := ParseX509CertificatesFromPEM(pemCertificate)
	if err != nil {
		t.Fatalf("ParseX509CertificatesFromPEM() failed: %v", err)
	}
	if len(certificates) != 1 {
		t.Fatalf("len(certificates) = %d, want 1", len(certificates))
	}
}

func TestBuildCertificateInfo(t *testing.T) {
	derCertificate := generateTestCertificateDER(t)
	certificates, err := ParseX509CertificatesFromDER([][]byte{derCertificate})
	if err != nil {
		t.Fatalf("ParseX509CertificatesFromDER() failed: %v", err)
	}

	info, err := BuildCertificateInfo(certificates[0])
	if err != nil {
		t.Fatalf("BuildCertificateInfo() failed: %v", err)
	}

	if info.Subject == "" {
		t.Fatal("Subject must not be empty")
	}
	if info.Issuer == "" {
		t.Fatal("Issuer must not be empty")
	}
	if info.SHA256Fingerprint == "" {
		t.Fatal("SHA256Fingerprint must not be empty")
	}
	if len(info.DNSNames) == 0 || info.DNSNames[0] != testDNSName {
		t.Fatalf("DNSNames = %v, want first=%q", info.DNSNames, testDNSName)
	}
}

func generateTestCertificateDER(t *testing.T) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testCommonName},
		DNSNames:              []string{testDNSName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() failed: %v", err)
	}
	return certificateDER
}

func buildCertificateHandshakeMessage(derCertificate []byte) []byte {
	certificateEntry := make([]byte, 0, 3+len(derCertificate)+2)
	certificateEntry = appendUint24(certificateEntry, len(derCertificate))
	certificateEntry = append(certificateEntry, derCertificate...)
	certificateEntry = append(certificateEntry, 0x00, 0x00)

	body := []byte{0x00}
	body = appendUint24(body, len(certificateEntry))
	body = append(body, certificateEntry...)

	message := make([]byte, 0, protocol.HandshakeHeaderLen+len(body))
	message = append(message, byte(protocol.TypeCertificate))
	message = appendUint24(message, len(body))
	message = append(message, body...)
	return message
}

func appendUint24(dst []byte, value int) []byte {
	dst = append(dst, byte(value>>16))
	dst = append(dst, byte(value>>8))
	dst = append(dst, byte(value))
	return dst
}
