package handshake

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
 */
type CertificateVerify struct {
	SignatureAlgorithm protocol.SignatureScheme
	Signature          []byte
}

func (m *CertificateVerify) Unmarshal(data []byte) error {
	if len(data) >= protocol.HandshakeHeaderLen && protocol.HandshakeType(data[0]) == protocol.TypeCertificateVerify {
		data = data[protocol.HandshakeHeaderLen:]
	}

	s := cryptobyte.String(data)

	var sigAlg uint16
	if !s.ReadUint16(&sigAlg) {
		return errors.New("failed to read signature algorithm")
	}
	m.SignatureAlgorithm = protocol.SignatureScheme(sigAlg)

	var signature cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&signature) || !s.Empty() {
		return errors.New("failed to read signature")
	}

	m.Signature = make([]byte, len(signature))
	copy(m.Signature, signature)

	return nil
}
