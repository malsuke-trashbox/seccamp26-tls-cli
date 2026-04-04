package handshake

import (
	"errors"
	"fmt"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.3
 */
type KeyUpdate struct {
	UpdateRequested bool
}

func (m *KeyUpdate) Type() protocol.HandshakeType {
	return protocol.TypeKeyUpdate
}

func (m *KeyUpdate) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(uint8(protocol.TypeKeyUpdate))

	b.AddUint24(1) // length: 1 byte for request_update
	if m.UpdateRequested {
		b.AddUint8(1)
	} else {
		b.AddUint8(0)
	}

	result, _ := b.Bytes()
	return result
}

func (m *KeyUpdate) Unmarshal(data []byte) error {
	if len(data) >= protocol.HandshakeHeaderLen && protocol.HandshakeType(data[0]) == protocol.TypeKeyUpdate {
		data = data[protocol.HandshakeHeaderLen:]
	}

	s := cryptobyte.String(data)

	if len(s) != 1 {
		return fmt.Errorf("invalid KeyUpdate length: %d", len(s))
	}

	var requestUpdate uint8
	if !s.ReadUint8(&requestUpdate) {
		return errors.New("failed to read KeyUpdate request")
	}

	switch requestUpdate {
	case 0:
		m.UpdateRequested = false
	case 1:
		m.UpdateRequested = true
	default:
		return fmt.Errorf("invalid KeyUpdate request value: %d", requestUpdate)
	}

	return nil
}
