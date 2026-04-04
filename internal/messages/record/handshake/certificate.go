package handshake

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
 */
type Certificate struct {
	Certificates [][]byte
}

func (m *Certificate) Unmarshal(data []byte) error {
	*m = Certificate{}

	if len(data) >= protocol.HandshakeHeaderLen && protocol.HandshakeType(data[0]) == protocol.TypeCertificate {
		data = data[protocol.HandshakeHeaderLen:]
	}

	s := cryptobyte.String(data)

	var context cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&context) || len(context) != 0 {
		return errors.New("invalid certificate context")
	}

	var certList cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&certList) || !s.Empty() {
		return errors.New("failed to read certificate list")
	}

	for !certList.Empty() {
		var cert cryptobyte.String
		if !certList.ReadUint24LengthPrefixed(&cert) {
			return errors.New("failed to read certificate")
		}

		var exts cryptobyte.String
		if !certList.ReadUint16LengthPrefixed(&exts) {
			return errors.New("failed to read certificate extensions")
		}

		certCopy := make([]byte, len(cert))
		copy(certCopy, cert)
		m.Certificates = append(m.Certificates, certCopy)
	}

	return nil
}
