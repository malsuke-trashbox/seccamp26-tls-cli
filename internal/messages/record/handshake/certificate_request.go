package handshake

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
 */
type CertificateRequest struct {
	SupportedSignatureAlgorithms     []protocol.SignatureScheme
	SupportedSignatureAlgorithmsCert []protocol.SignatureScheme
	CertificateAuthorities           [][]byte
}

func (m *CertificateRequest) Unmarshal(data []byte) error {
	*m = CertificateRequest{}

	if len(data) >= protocol.HandshakeHeaderLen && protocol.HandshakeType(data[0]) == protocol.TypeCertificateRequest {
		data = data[protocol.HandshakeHeaderLen:]
	}

	s := cryptobyte.String(data)

	var context cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&context) || len(context) != 0 {
		return errors.New("invalid certificate request context")
	}

	var extData cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extData) || !s.Empty() {
		return errors.New("failed to read certificate request extensions")
	}

	exts, ok := extensions.UnmarshalExtensions([]byte(extData))
	if !ok {
		return errors.New("failed to unmarshal extensions")
	}

	for _, ext := range exts {
		switch ext.Type {
		case protocol.ExtSignatureAlgorithms:
			sigAlgs, ok := extensions.ParseSignatureAlgorithms(ext.Payload)
			if !ok {
				return errors.New("failed to parse signature_algorithms extension")
			}
			m.SupportedSignatureAlgorithms = sigAlgs
		case protocol.ExtSignatureAlgorithmsCert:
			sigAlgs, ok := extensions.ParseSignatureAlgorithms(ext.Payload)
			if !ok {
				return errors.New("failed to parse signature_algorithms_cert extension")
			}
			m.SupportedSignatureAlgorithmsCert = sigAlgs
		case protocol.ExtCertificateAuthorities:
			cas, ok := ParseCertificateAuthorities(ext.Payload)
			if !ok {
				return errors.New("failed to parse certificate_authorities extension")
			}
			m.CertificateAuthorities = cas
		}
	}

	return nil
}

func ParseCertificateAuthorities(payload []byte) ([][]byte, bool) {
	s := cryptobyte.String(payload)
	var caList cryptobyte.String

	if !s.ReadUint16LengthPrefixed(&caList) || len(caList) == 0 || !s.Empty() {
		return nil, false
	}

	var cas [][]byte
	for !caList.Empty() {
		var ca cryptobyte.String
		if !caList.ReadUint16LengthPrefixed(&ca) || len(ca) == 0 {
			return nil, false
		}
		caCopy := make([]byte, len(ca))
		copy(caCopy, ca)
		cas = append(cas, caCopy)
	}

	return cas, true
}
