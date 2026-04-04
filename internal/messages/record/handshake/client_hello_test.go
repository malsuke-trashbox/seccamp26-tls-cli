package handshake_test

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestNewClientHello(t *testing.T) {
	ext := extensions.NewServerNameExtension("example.com")
	ch := handshake.NewClientHello([32]byte{}, []extensions.Extension{ext})
	if ch == nil {
		t.Fatal("NewClientHello returned a nil ClientHello")
	}
	if ch.ProtocolVersion != protocol.TLS_VERSION_1_2 {
		t.Errorf("Expected LegacyVersion to be %v, but got %v", protocol.TLS_VERSION_1_2, ch.ProtocolVersion)
	}
	if len(ch.Random) != 32 {
		t.Errorf("Expected Random to be 32 bytes, but got %d", len(ch.Random))
	}
	if len(ch.LegacySessionID) != 0 {
		t.Errorf("Expected LegacySessionID to be empty, but got %d bytes", len(ch.LegacySessionID))
	}
	expectedCipherSuites := []protocol.CipherSuite{protocol.TLS_AES_128_GCM_SHA256}
	if !equalCipherSuites(ch.CipherSuites, expectedCipherSuites) {
		t.Errorf("Expected CipherSuites to be %v, but got %v", expectedCipherSuites, ch.CipherSuites)
	}
	expectedCompressionMethods := []byte{0x00}
	if !bytes.Equal(ch.LegacyCompressionMethods, expectedCompressionMethods) {
		t.Errorf("Expected LegacyCompressionMethods to be %v, but got %v", expectedCompressionMethods, ch.LegacyCompressionMethods)
	}
	if len(ch.Extensions) != 1 {
		t.Errorf("Expected 1 extension, but got %d", len(ch.Extensions))
	}
}

func TestClientHelloMarshal(t *testing.T) {
	ext := extensions.NewServerNameExtension("example.com")
	var random [32]byte
	for i := 0; i < 32; i++ {
		random[i] = byte(i)
	}
	ch := handshake.NewClientHello(random, []extensions.Extension{ext})

	marshaled := ch.Marshal()

	// Expected structure:
	// LegacyVersion (2 bytes)
	// Random (32 bytes)
	// LegacySessionID length (1 byte)
	// LegacySessionID (0 bytes)
	// CipherSuites length (2 bytes)
	// CipherSuites (2 bytes)
	// LegacyCompressionMethods length (1 byte)
	// LegacyCompressionMethods (1 byte)
	// Extensions length (2 bytes)
	// Extensions (variable)

	expected_len_without_ext := 2 + 32 + 1 + 0 + 2 + 2 + 1 + 1 + 2
	ext_marshaled := ext.Marshal()
	expected_len := expected_len_without_ext + len(ext_marshaled)

	if len(marshaled) < expected_len_without_ext {
		t.Fatalf("Marshaled ClientHello is too short: got %d, expected at least %d", len(marshaled), expected_len)
	}

	// LegacyVersion
	if v := protocol.TLSVersion(uint16(marshaled[0])<<8 | uint16(marshaled[1])); v != protocol.TLS_VERSION_1_2 {
		t.Errorf("Expected LegacyVersion %v, got %v", protocol.TLS_VERSION_1_2, v)
	}

	// Random
	if !bytes.Equal(marshaled[2:34], random[:]) {
		t.Error("Random field is not marshaled correctly")
	}

	// LegacySessionID length
	if marshaled[34] != 0 {
		t.Errorf("Expected LegacySessionID length 0, got %d", marshaled[34])
	}

	// CipherSuites length
	if val := int(marshaled[35])<<8 | int(marshaled[36]); val != 2 {
		t.Errorf("Expected CipherSuites length 2, got %d", val)
	}

	// CipherSuite
	if cs := protocol.CipherSuite(uint16(marshaled[37])<<8 | uint16(marshaled[38])); cs != protocol.TLS_AES_128_GCM_SHA256 {
		t.Errorf("Expected CipherSuite %v, got %v", protocol.TLS_AES_128_GCM_SHA256, cs)
	}

	// LegacyCompressionMethods length
	if marshaled[39] != 1 {
		t.Errorf("Expected LegacyCompressionMethods length 1, got %d", marshaled[39])
	}

	// LegacyCompressionMethods
	if marshaled[40] != 0 {
		t.Errorf("Expected LegacyCompressionMethods 0, got %d", marshaled[40])
	}

	// Extensions length
	ext_len := int(marshaled[41])<<8 | int(marshaled[42])
	if ext_len != len(ext_marshaled) {
		t.Errorf("Expected Extensions length %d, got %d", len(ext_marshaled), ext_len)
	}

	// Extensions
	if !bytes.Equal(marshaled[43:], ext_marshaled) {
		t.Error("Extensions not marshaled correctly")
	}

	if len(marshaled) != expected_len {
		t.Errorf("Expected total marshaled length %d, got %d", expected_len, len(marshaled))
	}
}

func equalCipherSuites(a, b []protocol.CipherSuite) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
