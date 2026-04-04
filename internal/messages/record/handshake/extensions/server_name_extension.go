package extensions

import (
	"errors"
	"strings"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * ServerName represents the server_name extension (SNI).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6066#section-3
 */
type ServerName struct {
	ServerName string
}

func (s *ServerName) Type() protocol.ExtensionType {
	return protocol.ExtServerName
}

func (s *ServerName) MarshalPayload() []byte {
	b := cryptobyte.NewBuilder(nil)
	// ServerNameList
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		// NameType: host_name (0)
		b.AddUint8(0)
		// HostName
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(s.ServerName))
		})
	})
	result, _ := b.Bytes()
	return result
}

func (s *ServerName) Unmarshal(payload []byte) error {
	name, ok := ParseServerName(payload)
	if !ok {
		return errors.New("failed to parse server name")
	}
	s.ServerName = name
	return nil
}

func NewServerNameExtension(servername string) Extension {
	return NewExtension(&ServerName{ServerName: servername})
}

func ParseServerName(payload []byte) (string, bool) {
	s := cryptobyte.String(payload)
	var nameList cryptobyte.String

	if !s.ReadUint16LengthPrefixed(&nameList) {
		return "", false
	}

	for !nameList.Empty() {
		var nameType uint8
		var name cryptobyte.String

		if !nameList.ReadUint8(&nameType) {
			return "", false
		}
		if !nameList.ReadUint16LengthPrefixed(&name) {
			return "", false
		}

		if nameType != 0 {
			continue
		}

		serverName := string(name)
		if strings.HasSuffix(serverName, ".") {
			return "", false
		}
		return serverName, true
	}

	return "", true
}
