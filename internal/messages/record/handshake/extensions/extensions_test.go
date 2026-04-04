package extensions_test

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestExtensionMarshal(t *testing.T) {
	correctPayload := []byte{0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74}
	ext := &extensions.Extension{
		Type:    protocol.ExtServerName,
		Payload: correctPayload,
	}
	marshaled := ext.Marshal()
	expected := []byte{
		0x00, 0x00, // ExtensionType
		0x00, 0x0e, // Payload Length (14)
	}
	expected = append(expected, correctPayload...)

	if !bytes.Equal(marshaled, expected) {
		t.Errorf("Extension.Marshal() = %x, want %x", marshaled, expected)
	}
}

func TestUnmarshalExtensions(t *testing.T) {
	data := []byte{
		0x00, 0x00, // ExtensionType: server_name
		0x00, 0x0e, // Length
		0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
		0x00, 0x0a, // ExtensionType: supported_groups
		0x00, 0x04, // Length
		0x00, 0x02, 0x00, 0x1d,
	}

	exts, ok := extensions.UnmarshalExtensions(data)
	if !ok {
		t.Fatalf("UnmarshalExtensions failed")
	}

	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, but got %d", len(exts))
	}

	if exts[0].Type != protocol.ExtServerName {
		t.Errorf("expected first extension type %v, but got %v", protocol.ExtServerName, exts[0].Type)
	}

	expectedPayload1 := data[4:18]
	if !bytes.Equal(exts[0].Payload, expectedPayload1) {
		t.Errorf("expected first extension payload %x, but got %x", expectedPayload1, exts[0].Payload)
	}

	if exts[1].Type != protocol.ExtSupportedCurves {
		t.Errorf("expected second extension type %v, but got %v", protocol.ExtSupportedCurves, exts[1].Type)
	}

	expectedPayload2 := data[22:]
	if !bytes.Equal(exts[1].Payload, expectedPayload2) {
		t.Errorf("expected second extension payload %x, but got %x", expectedPayload2, exts[1].Payload)
	}
}
