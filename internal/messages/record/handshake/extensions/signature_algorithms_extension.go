package extensions

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * SignatureAlgorithms represents the signature_algorithms extension.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
 */
type SignatureAlgorithms struct {
	Algorithms []protocol.SignatureScheme
}

func (s *SignatureAlgorithms) Type() protocol.ExtensionType {
	return protocol.ExtSignatureAlgorithms
}

func (s *SignatureAlgorithms) MarshalPayload() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, alg := range s.Algorithms {
			b.AddUint16(uint16(alg))
		}
	})
	result, _ := b.Bytes()
	return result
}

func (s *SignatureAlgorithms) Unmarshal(payload []byte) error {
	algs, ok := ParseSignatureAlgorithms(payload)
	if !ok {
		return errors.New("failed to parse signature algorithms")
	}
	s.Algorithms = algs
	return nil
}

func NewSignatureAlgorithmsExtension() Extension {
	return NewExtension(&SignatureAlgorithms{
		Algorithms: []protocol.SignatureScheme{
			protocol.ECDSAWithP256AndSHA256,
			protocol.PSSWithSHA256,
			protocol.PKCS1WithSHA256,
			protocol.Ed25519,
		},
	})
}

func ParseSignatureAlgorithms(payload []byte) ([]protocol.SignatureScheme, bool) {
	s := cryptobyte.String(payload)
	var sigList cryptobyte.String

	if !s.ReadUint16LengthPrefixed(&sigList) {
		return nil, false
	}

	if len(sigList) == 0 || len(sigList)%2 != 0 {
		return nil, false
	}

	var sigAlgs []protocol.SignatureScheme
	for !sigList.Empty() {
		var sig uint16
		if !sigList.ReadUint16(&sig) {
			return nil, false
		}
		sigAlgs = append(sigAlgs, protocol.SignatureScheme(sig))
	}

	return sigAlgs, true
}
