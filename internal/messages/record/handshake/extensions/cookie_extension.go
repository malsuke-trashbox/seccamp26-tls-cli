package extensions

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * Cookie represents the cookie extension.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
 */
type Cookie struct {
	Cookie []byte
}

func (c *Cookie) Type() protocol.ExtensionType {
	return protocol.ExtCookie
}

func (c *Cookie) MarshalPayload() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.Cookie)
	})
	result, _ := b.Bytes()
	return result
}

func (c *Cookie) Unmarshal(payload []byte) error {
	cookie, ok := ParseCookie(payload)
	if !ok {
		return errors.New("failed to parse cookie")
	}
	c.Cookie = cookie
	return nil
}

func ParseCookie(payload []byte) ([]byte, bool) {
	s := cryptobyte.String(payload)
	var cookie cryptobyte.String

	if !s.ReadUint16LengthPrefixed(&cookie) {
		return nil, false
	}
	if len(cookie) == 0 {
		return nil, false
	}
	if !s.Empty() {
		return nil, false
	}

	result := make([]byte, len(cookie))
	copy(result, cookie)
	return result, true
}
