package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
)

var (
	ErrNoCertificates = errors.New("tls: no certificates")
	ErrNilCertificate = errors.New("tls: certificate is nil")
)

// CertificateInfo is a compact and readable summary of x509.Certificate.
type CertificateInfo struct {
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	DNSNames           []string
	SHA256Fingerprint  string
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm
}

// ParseCertificateMessage parses a TLS Certificate handshake message.
func ParseCertificateMessage(data []byte) (handshake.Certificate, error) {
	var message handshake.Certificate
	if err := message.Unmarshal(data); err != nil {
		return handshake.Certificate{}, fmt.Errorf("tls: failed to parse certificate message: %w", err)
	}
	return message, nil
}

// ParseX509CertificatesFromHandshakeMessage parses and decodes x509 certificates from a TLS Certificate handshake message.
func ParseX509CertificatesFromHandshakeMessage(data []byte) ([]*x509.Certificate, error) {
	message, err := ParseCertificateMessage(data)
	if err != nil {
		return nil, err
	}
	return ParseX509CertificatesFromDER(message.Certificates)
}

// ParseX509CertificatesFromDER parses certificate chain from DER-encoded certificates.
func ParseX509CertificatesFromDER(certificatesDER [][]byte) ([]*x509.Certificate, error) {
	if len(certificatesDER) == 0 {
		return nil, ErrNoCertificates
	}

	certificates := make([]*x509.Certificate, 0, len(certificatesDER))
	for index, certificateDER := range certificatesDER {
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return nil, fmt.Errorf("tls: failed to parse certificate[%d]: %w", index, err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// ParseX509CertificatesFromPEM parses certificate chain from PEM data.
func ParseX509CertificatesFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	if len(pemData) == 0 {
		return nil, ErrNoCertificates
	}

	certificates := make([]*x509.Certificate, 0)
	rest := pemData
	for len(rest) > 0 {
		block, remain := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remain

		if block.Type != "CERTIFICATE" {
			continue
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tls: failed to parse PEM certificate: %w", err)
		}
		certificates = append(certificates, certificate)
	}

	if len(certificates) == 0 {
		return nil, ErrNoCertificates
	}
	return certificates, nil
}

// FirstCertificate returns the first certificate in the chain.
func FirstCertificate(certificates []*x509.Certificate) (*x509.Certificate, error) {
	if len(certificates) == 0 {
		return nil, ErrNoCertificates
	}
	if certificates[0] == nil {
		return nil, ErrNilCertificate
	}
	return certificates[0], nil
}

// SHA256Fingerprint returns a lowercase hex SHA-256 fingerprint of certificate raw bytes.
func SHA256Fingerprint(certificate *x509.Certificate) (string, error) {
	if certificate == nil {
		return "", ErrNilCertificate
	}
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// BuildCertificateInfo builds a summary struct for one certificate.
func BuildCertificateInfo(certificate *x509.Certificate) (CertificateInfo, error) {
	if certificate == nil {
		return CertificateInfo{}, ErrNilCertificate
	}

	fingerprint, err := SHA256Fingerprint(certificate)
	if err != nil {
		return CertificateInfo{}, err
	}

	info := CertificateInfo{
		Subject:            certificate.Subject.String(),
		Issuer:             certificate.Issuer.String(),
		NotBefore:          certificate.NotBefore,
		NotAfter:           certificate.NotAfter,
		DNSNames:           append([]string(nil), certificate.DNSNames...),
		SHA256Fingerprint:  fingerprint,
		PublicKeyAlgorithm: certificate.PublicKeyAlgorithm,
		SignatureAlgorithm: certificate.SignatureAlgorithm,
	}
	return info, nil
}

// BuildCertificateInfos builds certificate summaries for all certificates.
func BuildCertificateInfos(certificates []*x509.Certificate) ([]CertificateInfo, error) {
	if len(certificates) == 0 {
		return nil, ErrNoCertificates
	}

	infos := make([]CertificateInfo, 0, len(certificates))
	for index, certificate := range certificates {
		info, err := BuildCertificateInfo(certificate)
		if err != nil {
			return nil, fmt.Errorf("tls: failed to build certificate info[%d]: %w", index, err)
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// IsExpiredAt reports whether a certificate is expired at the given time.
func IsExpiredAt(certificate *x509.Certificate, at time.Time) (bool, error) {
	if certificate == nil {
		return false, ErrNilCertificate
	}
	return at.Before(certificate.NotBefore) || at.After(certificate.NotAfter), nil
}
