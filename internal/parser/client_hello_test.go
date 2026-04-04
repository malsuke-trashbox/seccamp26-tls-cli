package parser

import (
	"strings"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestBuildServerAddress(t *testing.T) {
	address, err := BuildServerAddress("www.example.com", DefaultTLSPort)
	if err != nil {
		t.Fatalf("BuildServerAddress() failed: %v", err)
	}
	if !strings.Contains(address, ":443") {
		t.Fatalf("address = %q, want :443", address)
	}
}

func TestNewDefaultClientHelloRecord(t *testing.T) {
	random, err := key.GenerateRandom32Bytes()
	if err != nil {
		t.Fatalf("GenerateRandom32Bytes() failed: %v", err)
	}

	_, publicKey, err := key.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair() failed: %v", err)
	}

	rec, err := NewDefaultClientHelloRecord(random, "www.example.com", publicKey.Bytes())
	if err != nil {
		t.Fatalf("NewDefaultClientHelloRecord() failed: %v", err)
	}

	if rec.Type != protocol.Handshake {
		t.Fatalf("record type = %v, want %v", rec.Type, protocol.Handshake)
	}

	if len(rec.Payload) < protocol.HandshakeHeaderLen {
		t.Fatalf("record payload too short: %d", len(rec.Payload))
	}

	if protocol.HandshakeType(rec.Payload[0]) != protocol.TypeClientHello {
		t.Fatalf("handshake type = %v, want %v", protocol.HandshakeType(rec.Payload[0]), protocol.TypeClientHello)
	}
}

func TestDefaultClientHelloExtensionsInvalidKey(t *testing.T) {
	_, err := DefaultClientHelloExtensions("www.example.com", []byte{0x01})
	if err == nil {
		t.Fatal("DefaultClientHelloExtensions() should fail for invalid key length")
	}
}
