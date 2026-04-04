package handshake

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

var ErrHandshakeBodyTooLarge = errors.New("tls: handshake body too large")

/**
 * Handshake represents a TLS handshake message.
 *
 * Handshake messages are wrapped by the Record layer:
 *   Record
 *     └─ Handshake (4 bytes header + body)
 *          └─ ClientHello / ServerHello / Certificate / etc.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4
 *
 * struct {
 *     HandshakeType msg_type;    // 1 byte
 *     uint24 length;             // 3 bytes
 *     select (Handshake.msg_type) {
 *         case client_hello:          ClientHello;
 *         case server_hello:          ServerHello;
 *         case certificate:           Certificate;
 *         case certificate_verify:    CertificateVerify;
 *         case finished:              Finished;
 *         ...
 *     };
 * } Handshake;
 */
type Handshake struct {
	HandshakeType protocol.HandshakeType
	Length        [3]byte
	Body          []byte
}

type HandshakeMessage interface {
	Marshal() []byte
	Type() protocol.HandshakeType
}

type HandshakeUnmarshaler interface {
	Unmarshal(data []byte) error
}

type HandshakeCodec interface {
	HandshakeMessage
	HandshakeUnmarshaler
}

func NewHandshake(msg HandshakeMessage) (*Handshake, error) {
	body := msg.Marshal()
	length := len(body)
	if length > 0xffffff {
		return nil, ErrHandshakeBodyTooLarge
	}
	return &Handshake{
		HandshakeType: msg.Type(),
		Length:        [3]byte{byte(length >> 16), byte((length >> 8) & 0xff), byte(length & 0xff)},
		Body:          body,
	}, nil
}

func (h *Handshake) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(uint8(h.HandshakeType))
	b.AddBytes(h.Length[:])
	b.AddBytes(h.Body)
	result, _ := b.Bytes()
	return result
}
