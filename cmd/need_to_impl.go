package main

import (
	"crypto/ecdh"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/utils"
)

func NewClientHelloRecord(pub *ecdh.PublicKey) (*record.TLSPlaintext, error) {
	hs, err := handshake.NewHandshake(&handshake.ClientHello{
		ProtocolVersion:          protocol.TLS_VERSION_1_2,
		Random:                   utils.GenerateRandom32Bytes(),
		LegacySessionID:          []byte{},
		CipherSuites:             []protocol.CipherSuite{protocol.TLS_CHACHA20_POLY1305_SHA256},
		LegacyCompressionMethods: []byte{0x00},
		Extensions: []extensions.Extension{
			extensions.NewServerNameExtension("www.example.com"),
			extensions.NewSupportedVersionsExtension(),
			extensions.NewSupportedGroupsExtension(),
			extensions.NewSignatureAlgorithmsExtension(),
			extensions.NewKeyShareExtension(pub.Bytes()),
		},
	})
	if err != nil {
		return nil, err
	}
	rc, err := record.NewTLSPlaintext(
		protocol.Handshake,
		hs.Marshal(),
	)
	if err != nil {
		return nil, err
	}

	return rc, err
}
