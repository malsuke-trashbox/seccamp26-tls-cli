package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/certifi/gocertifi"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

const tls13ServerCertificateVerifyContext = "TLS 1.3, server CertificateVerify"

var (
	ErrNilCertificateMessage               = errors.New("tls: certificate message is nil")
	ErrEmptyServerName                     = errors.New("tls: server name is empty")
	ErrEmptyCertificateVerifySignature     = errors.New("tls: certificate verify signature is empty")
	ErrEmptyCertificateVerifyTranscript    = errors.New("tls: certificate verify transcript is empty")
	ErrInvalidCertificateVerifySignature   = errors.New("tls: invalid certificate verify signature")
	ErrUnsupportedCertificateVerifyKeyType = errors.New("tls: unsupported certificate public key type")
)

func VerifyServerCertificateChainWithCertifi(
	certificateMessage *handshake.Certificate,
	serverName string,
) (*x509.Certificate, []*x509.Certificate, error) {
	if certificateMessage == nil {
		return nil, nil, ErrNilCertificateMessage
	}
	if serverName == "" {
		return nil, nil, ErrEmptyServerName
	}

	certificates, err := ParseX509CertificatesFromDER(certificateMessage.Certificates)
	if err != nil {
		return nil, nil, err
	}

	leaf, err := FirstCertificate(certificates)
	if err != nil {
		return nil, nil, err
	}

	roots, err := gocertifi.CACerts()
	if err != nil {
		return nil, nil, fmt.Errorf("tls: failed to load certifi roots: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}

	opts := x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if _, err := leaf.Verify(opts); err != nil {
		return nil, certificates, fmt.Errorf("tls: failed to verify certificate chain: %w", err)
	}

	return leaf, certificates, nil
}

func VerifyTLS13ServerCertificateVerify(
	leafCertificate *x509.Certificate,
	signatureAlgorithm protocol.SignatureScheme,
	signature []byte,
	transcript []byte,
) error {
	if leafCertificate == nil {
		return ErrNilCertificate
	}
	if len(signature) == 0 {
		return ErrEmptyCertificateVerifySignature
	}
	if len(transcript) == 0 {
		return ErrEmptyCertificateVerifyTranscript
	}

	transcriptHash := sha256.Sum256(transcript)
	signedContent := buildTLS13ServerCertificateVerifyContent(transcriptHash[:])
	digest := sha256.Sum256(signedContent)

	switch signatureAlgorithm {
	case protocol.Ed25519:
		publicKey, ok := leafCertificate.PublicKey.(ed25519.PublicKey)
		if !ok {
			return ErrUnsupportedCertificateVerifyKeyType
		}
		if !ed25519.Verify(publicKey, signedContent, signature) {
			return ErrInvalidCertificateVerifySignature
		}
		return nil

	case protocol.ECDSAWithP256AndSHA256:
		publicKey, ok := leafCertificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrUnsupportedCertificateVerifyKeyType
		}
		if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
			return ErrInvalidCertificateVerifySignature
		}
		return nil

	case protocol.PSSWithSHA256:
		publicKey, ok := leafCertificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return ErrUnsupportedCertificateVerifyKeyType
		}
		if err := rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}); err != nil {
			return ErrInvalidCertificateVerifySignature
		}
		return nil

	case protocol.PKCS1WithSHA256:
		publicKey, ok := leafCertificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return ErrUnsupportedCertificateVerifyKeyType
		}
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
			return ErrInvalidCertificateVerifySignature
		}
		return nil

	default:
		return fmt.Errorf("tls: unsupported certificate verify signature algorithm: %s", signatureAlgorithm)
	}
}

func buildTLS13ServerCertificateVerifyContent(transcriptHash []byte) []byte {
	content := make([]byte, 0, 64+len(tls13ServerCertificateVerifyContext)+1+len(transcriptHash))
	for i := 0; i < 64; i++ {
		content = append(content, 0x20)
	}
	content = append(content, []byte(tls13ServerCertificateVerifyContext)...)
	content = append(content, 0x00)
	content = append(content, transcriptHash...)
	return content
}
