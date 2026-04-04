package handshake

import (
	"errors"
	"fmt"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
 */
type EncryptedExtensions struct {
	Extensions    []extensions.Extension
	ServerNameAck bool
}

func (m *EncryptedExtensions) Unmarshal(data []byte) error {
	*m = EncryptedExtensions{}

	if len(data) >= protocol.HandshakeHeaderLen && protocol.HandshakeType(data[0]) == protocol.TypeEncryptedExtensions {
		s := cryptobyte.String(data[1:4])
		var msgLen uint32
		if !s.ReadUint24(&msgLen) {
			return errors.New("failed to read encrypted extensions message length")
		}
		data = data[protocol.HandshakeHeaderLen : protocol.HandshakeHeaderLen+int(msgLen)]
	}

	s := cryptobyte.String(data)

	var extData cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extData) {
		return errors.New("failed to read encrypted extensions")
	}

	exts, ok := extensions.UnmarshalExtensions([]byte(extData))
	if !ok {
		return errors.New("failed to unmarshal extensions")
	}

	seenExts := make(map[protocol.ExtensionType]bool)
	for _, ext := range exts {
		if seenExts[ext.Type] {
			return fmt.Errorf("duplicate extension: %s", ext.Type)
		}
		seenExts[ext.Type] = true

		switch ext.Type {
		case protocol.ExtServerName:
			if len(ext.Payload) != 0 {
				return errors.New("server_name extension in EncryptedExtensions must be empty")
			}
			m.ServerNameAck = true
		default:
			m.Extensions = append(m.Extensions, ext)
		}
	}

	return nil
}
