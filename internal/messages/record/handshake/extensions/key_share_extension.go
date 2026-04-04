package extensions

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * KeyShareExtension represents the key_share extension for ClientHello.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
 */
type KeyShareExtension struct {
	KeyShares []KeyShare
}

type KeyShare struct {
	Group protocol.CurveID
	Data  []byte
}

func (k *KeyShareExtension) Type() protocol.ExtensionType {
	return protocol.ExtKeyShare
}

func (k *KeyShareExtension) MarshalPayload() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, ks := range k.KeyShares {
			b.AddUint16(uint16(ks.Group))
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(ks.Data)
			})
		}
	})
	result, _ := b.Bytes()
	return result
}

func (k *KeyShareExtension) Unmarshal(payload []byte) error {
	shares, ok := ParseKeyShareClient(payload)
	if !ok {
		return errors.New("failed to parse key shares")
	}
	k.KeyShares = shares
	return nil
}

func NewKeyShareExtension(publicKey []byte) Extension {
	return NewExtension(&KeyShareExtension{
		KeyShares: []KeyShare{
			{Group: protocol.X25519, Data: publicKey},
		},
	})
}

func ParseKeyShareClient(payload []byte) ([]KeyShare, bool) {
	s := cryptobyte.String(payload)
	var shareList cryptobyte.String

	if !s.ReadUint16LengthPrefixed(&shareList) {
		return nil, false
	}

	var keyShares []KeyShare
	for !shareList.Empty() {
		var group uint16
		var data cryptobyte.String

		if !shareList.ReadUint16(&group) {
			return nil, false
		}
		if !shareList.ReadUint16LengthPrefixed(&data) {
			return nil, false
		}

		keyShares = append(keyShares, KeyShare{
			Group: protocol.CurveID(group),
			Data:  []byte(data),
		})
	}

	return keyShares, true
}

func ParseKeyShareServer(payload []byte) (KeyShare, protocol.CurveID, bool) {
	s := cryptobyte.String(payload)

	// HelloRetryRequest case: only contains selected_group (2 bytes)
	if len(payload) == 2 {
		var group uint16
		if !s.ReadUint16(&group) {
			return KeyShare{}, 0, false
		}
		return KeyShare{}, protocol.CurveID(group), true
	}
	var group uint16
	var data cryptobyte.String

	if !s.ReadUint16(&group) {
		return KeyShare{}, 0, false
	}
	if !s.ReadUint16LengthPrefixed(&data) {
		return KeyShare{}, 0, false
	}
	if !s.Empty() {
		return KeyShare{}, 0, false
	}

	return KeyShare{
		Group: protocol.CurveID(group),
		Data:  []byte(data),
	}, 0, true
}
