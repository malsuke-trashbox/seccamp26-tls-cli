package handshake

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
 */
type Finished struct {
	VerifyData []byte
}

func (m *Finished) Type() protocol.HandshakeType {
	return protocol.TypeFinished
}

func (m *Finished) Marshal() []byte {
	return m.VerifyData
}

func (m *Finished) Unmarshal(data []byte) error {
	if len(data) < 1 {
		return errors.New("data too short for Finished")
	}

	s := cryptobyte.String(data)

	var msgType uint8
	if !s.ReadUint8(&msgType) {
		return errors.New("failed to read Finished message type")
	}

	var verifyData cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&verifyData) || !s.Empty() {
		return errors.New("failed to read Finished verify data")
	}

	m.VerifyData = make([]byte, len(verifyData))
	copy(m.VerifyData, verifyData)

	return nil
}
