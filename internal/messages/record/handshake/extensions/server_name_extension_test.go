package extensions_test

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestNewServerNameExtension(t *testing.T) {
	servername := "example.com"
	ext := extensions.NewServerNameExtension(servername)

	if ext.Type != protocol.ExtServerName {
		t.Errorf("Expected extension type %v, but got %v", protocol.ExtServerName, ext.Type)
	}

	nameBytes := []byte(servername)
	nameLength := len(nameBytes)
	expectedServerNameListLength := 1 + 2 + nameLength
	expectedPayloadLength := 2 + expectedServerNameListLength

	if len(ext.Payload) != expectedPayloadLength {
		t.Fatalf("Expected payload length %d, but got %d", expectedPayloadLength, len(ext.Payload))
	}

	// ServerNameList length
	if val := int(ext.Payload[0])<<8 | int(ext.Payload[1]); val != expectedServerNameListLength {
		t.Errorf("Expected ServerNameList length %d, but got %d", expectedServerNameListLength, val)
	}

	// NameType
	if ext.Payload[2] != 0x00 { // host_name
		t.Errorf("Expected NameType 0x00, but got 0x%x", ext.Payload[2])
	}

	// HostName length
	if val := int(ext.Payload[3])<<8 | int(ext.Payload[4]); val != nameLength {
		t.Errorf("Expected HostName length %d, but got %d", nameLength, val)
	}

	// HostName
	if !bytes.Equal(ext.Payload[5:], nameBytes) {
		t.Errorf("Expected HostName %s, but got %s", servername, string(ext.Payload[5:]))
	}
}

func TestServerNameExtensionMarshal(t *testing.T) {
	servername := "example.com"
	ext := extensions.NewServerNameExtension(servername)
	marshaled := ext.Marshal()

	// Expected structure:
	// Type (2 bytes)
	// Payload length (2 bytes)
	// Payload (variable)

	expectedLength := 2 + 2 + len(ext.Payload)
	if len(marshaled) != expectedLength {
		t.Fatalf("Expected marshaled length %d, but got %d", expectedLength, len(marshaled))
	}

	// Type
	if val := protocol.ExtensionType(uint16(marshaled[0])<<8 | uint16(marshaled[1])); val != protocol.ExtServerName {
		t.Errorf("Expected extension type %v, but got %v", protocol.ExtServerName, val)
	}

	// Payload length
	if val := int(marshaled[2])<<8 | int(marshaled[3]); val != len(ext.Payload) {
		t.Errorf("Expected payload length %d, but got %d", len(ext.Payload), val)
	}

	// Payload
	if !bytes.Equal(marshaled[4:], ext.Payload) {
		t.Error("Payload not marshaled correctly")
	}
}
