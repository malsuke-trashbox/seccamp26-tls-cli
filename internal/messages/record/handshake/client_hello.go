package handshake

import (
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

const (
	clientRandomLength = 32
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
 */
type ClientHello struct {
	Original                 []byte
	ProtocolVersion          protocol.TLSVersion
	Random                   [clientRandomLength]byte
	LegacySessionID          []byte
	CipherSuites             []protocol.CipherSuite
	LegacyCompressionMethods []byte
	Extensions               []extensions.Extension
}

func (ch *ClientHello) Type() protocol.HandshakeType {
	return protocol.TypeClientHello
}

func NewClientHello(random [clientRandomLength]byte, exts []extensions.Extension) *ClientHello {
	return &ClientHello{
		ProtocolVersion:          protocol.TLS_VERSION_1_2,
		Random:                   random,
		LegacySessionID:          []byte{},
		CipherSuites:             []protocol.CipherSuite{protocol.TLS_AES_128_GCM_SHA256},
		LegacyCompressionMethods: []byte{0x00},
		Extensions:               exts,
	}
}

func (ch *ClientHello) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint16(uint16(ch.ProtocolVersion))
	b.AddBytes(ch.Random[:])
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ch.LegacySessionID)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, cs := range ch.CipherSuites {
			b.AddUint16(uint16(cs))
		}
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ch.LegacyCompressionMethods)
	})
	if len(ch.Extensions) > 0 {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, ext := range ch.Extensions {
				b.AddBytes(ext.Marshal())
			}
		})
	}

	result, _ := b.Bytes()
	return result
}
