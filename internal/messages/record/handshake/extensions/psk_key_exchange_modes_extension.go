package extensions

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

// PSKKeyExchangeMode represents a PSK key exchange mode
type PSKKeyExchangeMode uint8

const (
	PSKModePlain PSKKeyExchangeMode = 0 // psk_ke
	PSKModeDHE   PSKKeyExchangeMode = 1 // psk_dhe_ke
)

/**
 * PSKKeyExchangeModes represents the psk_key_exchange_modes extension.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
 */
type PSKKeyExchangeModes struct {
	Modes []PSKKeyExchangeMode
}

func (p *PSKKeyExchangeModes) Type() protocol.ExtensionType {
	return protocol.ExtPSKKeyExchangeModes
}

func (p *PSKKeyExchangeModes) MarshalPayload() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, m := range p.Modes {
			b.AddUint8(uint8(m))
		}
	})
	result, _ := b.Bytes()
	return result
}

func (p *PSKKeyExchangeModes) Unmarshal(payload []byte) error {
	modes, ok := ParsePSKKeyExchangeModes(payload)
	if !ok {
		return errors.New("failed to parse psk key exchange modes")
	}
	p.Modes = modes
	return nil
}

func NewPskKeyExchangeModesExtension() Extension {
	return NewExtension(&PSKKeyExchangeModes{
		Modes: []PSKKeyExchangeMode{PSKModeDHE},
	})
}

func ParsePSKKeyExchangeModes(payload []byte) ([]PSKKeyExchangeMode, bool) {
	s := cryptobyte.String(payload)
	var modeList cryptobyte.String

	if !s.ReadUint8LengthPrefixed(&modeList) {
		return nil, false
	}

	if len(modeList) == 0 {
		return nil, false
	}

	var modes []PSKKeyExchangeMode
	for !modeList.Empty() {
		var m uint8
		if !modeList.ReadUint8(&m) {
			return nil, false
		}
		modes = append(modes, PSKKeyExchangeMode(m))
	}

	return modes, true
}
