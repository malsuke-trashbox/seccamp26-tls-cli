package extensions

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * SupportedGroups represents the supported_groups extension.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
 */
type SupportedGroups struct {
	Groups []protocol.CurveID
}

func (s *SupportedGroups) Type() protocol.ExtensionType {
	return protocol.ExtSupportedCurves
}

func (s *SupportedGroups) MarshalPayload() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, g := range s.Groups {
			b.AddUint16(uint16(g))
		}
	})
	result, _ := b.Bytes()
	return result
}

func (s *SupportedGroups) Unmarshal(payload []byte) error {
	groups, ok := ParseSupportedCurves(payload)
	if !ok {
		return errors.New("failed to parse supported groups")
	}
	s.Groups = groups
	return nil
}

func NewSupportedGroupsExtension() Extension {
	return NewExtension(&SupportedGroups{
		Groups: []protocol.CurveID{protocol.X25519},
	})
}

func ParseSupportedCurves(payload []byte) ([]protocol.CurveID, bool) {
	s := cryptobyte.String(payload)
	var curveList cryptobyte.String

	if !s.ReadUint16LengthPrefixed(&curveList) {
		return nil, false
	}

	if len(curveList) == 0 || len(curveList)%2 != 0 {
		return nil, false
	}

	var curves []protocol.CurveID
	for !curveList.Empty() {
		var c uint16
		if !curveList.ReadUint16(&c) {
			return nil, false
		}
		curves = append(curves, protocol.CurveID(c))
	}

	return curves, true
}
