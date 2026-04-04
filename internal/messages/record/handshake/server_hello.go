package handshake

import (
	"errors"
	"fmt"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
 */
type ServerHello struct {
	Original          []byte
	ProtocolVersion   protocol.TLSVersion
	Random            [32]byte
	SessionID         []byte
	CipherSuite       protocol.CipherSuite
	CompressionMethod byte
	Extensions        []extensions.Extension
}

func (sh *ServerHello) Unmarshal(data []byte) error {

	sh.Original = make([]byte, len(data))
	copy(sh.Original, data)

	if len(data) >= protocol.HandshakeHeaderLen && protocol.HandshakeType(data[0]) == protocol.TypeServerHello {
		data = data[protocol.HandshakeHeaderLen:]
	}

	s := cryptobyte.String(data)

	var version uint16
	if !s.ReadUint16(&version) {
		return errors.New("failed to read ServerHello version")
	}
	sh.ProtocolVersion = protocol.TLSVersion(version)

	var random []byte
	if !s.ReadBytes(&random, 32) {
		return errors.New("failed to read ServerHello random")
	}
	copy(sh.Random[:], random)

	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return errors.New("failed to read ServerHello session ID")
	}
	sh.SessionID = make([]byte, len(sessionID))
	copy(sh.SessionID, sessionID)

	var cipherSuite uint16
	if !s.ReadUint16(&cipherSuite) {
		return errors.New("failed to read ServerHello cipher suite")
	}
	sh.CipherSuite = protocol.CipherSuite(cipherSuite)

	if !s.ReadUint8(&sh.CompressionMethod) {
		return errors.New("failed to read ServerHello compression method")
	}

	if s.Empty() {
		return nil
	}

	var extData cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extData) || !s.Empty() {
		return errors.New("failed to read ServerHello extensions")
	}

	exts, ok := extensions.UnmarshalExtensions([]byte(extData))
	if !ok {
		return errors.New("failed to unmarshal extensions")
	}

	sh.Extensions = exts

	seenExts := make(map[protocol.ExtensionType]bool)
	for _, ext := range exts {
		if seenExts[ext.Type] {
			return fmt.Errorf("duplicate extension: %s", ext.Type)
		}
		seenExts[ext.Type] = true

		switch ext.Type {
		case protocol.ExtSupportedVersions:
			if _, ok := extensions.ParseSupportedVersionsServer(ext.Payload); !ok {
				return errors.New("failed to parse supported_versions extension")
			}
		case protocol.ExtCookie:
			if _, ok := extensions.ParseCookie(ext.Payload); !ok {
				return errors.New("failed to parse cookie extension")
			}
		case protocol.ExtKeyShare:
			if _, _, ok := extensions.ParseKeyShareServer(ext.Payload); !ok {
				return errors.New("failed to parse key_share extension")
			}
		}
	}

	return nil
}

func (sh *ServerHello) SupportedVersion() (protocol.TLSVersion, error) {
	for _, ext := range sh.Extensions {
		if ext.Type != protocol.ExtSupportedVersions {
			continue
		}
		version, ok := extensions.ParseSupportedVersionsServer(ext.Payload)
		if !ok {
			return 0, fmt.Errorf("failed to parse %s extension", protocol.ExtSupportedVersions)
		}
		return version, nil
	}
	return 0, errors.New("supported_versions extension is missing")
}

func (sh *ServerHello) ServerShare() (extensions.KeyShare, error) {
	for _, ext := range sh.Extensions {
		if ext.Type != protocol.ExtKeyShare {
			continue
		}
		share, selectedGroup, ok := extensions.ParseKeyShareServer(ext.Payload)
		if !ok {
			return extensions.KeyShare{}, fmt.Errorf("failed to parse %s extension", protocol.ExtKeyShare)
		}
		if selectedGroup != 0 {
			return extensions.KeyShare{}, fmt.Errorf("%s extension contains selected group (hello retry request)", protocol.ExtKeyShare)
		}
		return share, nil
	}
	return extensions.KeyShare{}, errors.New("key_share extension is missing")
}
