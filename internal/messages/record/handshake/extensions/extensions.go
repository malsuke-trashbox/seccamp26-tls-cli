package extensions

import (
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
 */
type ExtensionData interface {
	Type() protocol.ExtensionType
	MarshalPayload() []byte
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
 */
type Extension struct {
	Type    protocol.ExtensionType
	Payload []byte
}

func NewExtension(data ExtensionData) Extension {
	return Extension{
		Type:    data.Type(),
		Payload: data.MarshalPayload(),
	}
}

func (e Extension) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(uint16(e.Type))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.Payload)
	})
	result, _ := b.Bytes()
	return result
}

func UnmarshalExtensions(data []byte) ([]Extension, bool) {
	var exts []Extension
	s := cryptobyte.String(data)

	for !s.Empty() {
		var extType uint16
		var payload cryptobyte.String

		if !s.ReadUint16(&extType) {
			return nil, false
		}
		if !s.ReadUint16LengthPrefixed(&payload) {
			return nil, false
		}

		ext := Extension{
			Type:    protocol.ExtensionType(extType),
			Payload: make([]byte, len(payload)),
		}
		copy(ext.Payload, payload)
		exts = append(exts, ext)
	}

	return exts, true
}
