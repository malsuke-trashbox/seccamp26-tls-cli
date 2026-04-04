package record

import (
	"errors"
)

/**
 * ChangeCipherSpec message structure.
 *
 * In TLS 1.3, the ChangeCipherSpec message is included primarily for
 * compatibility with middleboxes that expect it. It is sent at specific
 * points in the handshake to enable middlebox compatibility mode.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.3
 *
 * struct {
 *     enum { change_cipher_spec(1), (255) } type;
 * } ChangeCipherSpec;
 */
type ChangeCipherSpec struct {
	Type byte
}

// Unmarshal parses the binary representation of a ChangeCipherSpec message.
func (ccs *ChangeCipherSpec) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return errors.New("ChangeCipherSpec message too short")
	}

	ccs.Type = data[0]

	if ccs.Type != 1 {
		return errors.New("invalid ChangeCipherSpec type")
	}

	if len(data) > 1 {
		return errors.New("ChangeCipherSpec has trailing bytes")
	}

	return nil
}

// Marshal returns the binary representation of a ChangeCipherSpec message.
func (ccs *ChangeCipherSpec) Marshal() []byte {
	return []byte{ccs.Type}
}

// NewChangeCipherSpec creates a new ChangeCipherSpec message with type set to 1.
func NewChangeCipherSpec() *ChangeCipherSpec {
	return &ChangeCipherSpec{
		Type: 1,
	}
}
