package extensions

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * SupportedVersions represents the supported_versions extension.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
 */
type SupportedVersions struct {
	Versions []protocol.TLSVersion
}

func (s *SupportedVersions) Type() protocol.ExtensionType {
	return protocol.ExtSupportedVersions
}

func (s *SupportedVersions) MarshalPayload() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, v := range s.Versions {
			b.AddUint16(uint16(v))
		}
	})
	result, _ := b.Bytes()
	return result
}

func (s *SupportedVersions) Unmarshal(payload []byte) error {
	versions, ok := ParseSupportedVersionsClient(payload)
	if !ok {
		return errors.New("failed to parse supported versions")
	}
	s.Versions = make([]protocol.TLSVersion, len(versions))
	for i, v := range versions {
		s.Versions[i] = protocol.TLSVersion(v)
	}
	return nil
}

func NewSupportedVersionsExtension() Extension {
	return NewExtension(&SupportedVersions{
		Versions: []protocol.TLSVersion{protocol.TLS_VERSION_1_3},
	})
}

func ParseSupportedVersionsClient(payload []byte) ([]uint16, bool) {
	s := cryptobyte.String(payload)
	var versionList cryptobyte.String

	if !s.ReadUint8LengthPrefixed(&versionList) {
		return nil, false
	}

	if len(versionList) == 0 || len(versionList)%2 != 0 {
		return nil, false
	}

	var versions []uint16
	for !versionList.Empty() {
		var v uint16
		if !versionList.ReadUint16(&v) {
			return nil, false
		}
		versions = append(versions, v)
	}

	return versions, true
}

func ParseSupportedVersionsServer(payload []byte) (protocol.TLSVersion, bool) {
	if len(payload) != 2 {
		return 0, false
	}
	s := cryptobyte.String(payload)
	var v uint16
	if !s.ReadUint16(&v) {
		return 0, false
	}
	return protocol.TLSVersion(v), true
}
