package utils

import (
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

const handshakeSplitFirstPart = 10

func TestParseServerHelloFromBytes(t *testing.T) {
	serverHelloMessage := buildServerHelloHandshakeMessage()

	rec1, err := record.NewTLSPlaintext(protocol.Handshake, serverHelloMessage[:handshakeSplitFirstPart])
	if err != nil {
		t.Fatalf("NewTLSPlaintext(rec1) failed: %v", err)
	}

	changeCipherSpecRecord, err := record.NewTLSPlaintext(protocol.ChangeCipherSpec, []byte{0x01})
	if err != nil {
		t.Fatalf("NewTLSPlaintext(changeCipherSpec) failed: %v", err)
	}

	rec2, err := record.NewTLSPlaintext(protocol.Handshake, serverHelloMessage[handshakeSplitFirstPart:])
	if err != nil {
		t.Fatalf("NewTLSPlaintext(rec2) failed: %v", err)
	}

	raw := append([]byte{}, rec1.Marshal()...)
	raw = append(raw, changeCipherSpecRecord.Marshal()...)
	raw = append(raw, rec2.Marshal()...)

	serverHello, plaintextRecords, ciphertextRecords, err := ParseServerHelloFromBytes(raw)
	if err != nil {
		t.Fatalf("ParseServerHelloFromBytes() failed: %v", err)
	}

	if len(plaintextRecords) != 3 {
		t.Fatalf("len(plaintextRecords) = %d, want 3", len(plaintextRecords))
	}
	if len(ciphertextRecords) != 0 {
		t.Fatalf("len(ciphertextRecords) = %d, want 0", len(ciphertextRecords))
	}

	if serverHello.CipherSuite != protocol.TLS_AES_128_GCM_SHA256 {
		t.Fatalf("serverHello.CipherSuite = %v, want %v", serverHello.CipherSuite, protocol.TLS_AES_128_GCM_SHA256)
	}

	version, err := serverHello.SupportedVersion()
	if err != nil {
		t.Fatalf("SupportedVersion() failed: %v", err)
	}
	if version != protocol.TLS_VERSION_1_3 {
		t.Fatalf("supported version = %v, want %v", version, protocol.TLS_VERSION_1_3)
	}
}

func TestCollectHandshakeMessagesIncompleteHeader(t *testing.T) {
	rec, err := record.NewTLSPlaintext(protocol.Handshake, []byte{byte(protocol.TypeServerHello), 0x00, 0x00})
	if err != nil {
		t.Fatalf("NewTLSPlaintext() failed: %v", err)
	}

	_, err = CollectHandshakeMessages([]record.TLSPlaintext{*rec})
	if err == nil {
		t.Fatal("CollectHandshakeMessages() should fail for incomplete handshake header")
	}
}

func TestParseRecordsIncludesAlertInPlaintext(t *testing.T) {
	alertRecord, err := record.NewTLSPlaintext(protocol.Alert, []byte{0x02, byte(protocol.AlertHandshakeFailure)})
	if err != nil {
		t.Fatalf("NewTLSPlaintext(alert) failed: %v", err)
	}

	plaintextRecords, ciphertextRecords, err := ParseRecords(alertRecord.Marshal())
	if err != nil {
		t.Fatalf("ParseRecords() failed: %v", err)
	}

	if len(plaintextRecords) != 1 {
		t.Fatalf("len(plaintextRecords) = %d, want 1", len(plaintextRecords))
	}
	if len(ciphertextRecords) != 0 {
		t.Fatalf("len(ciphertextRecords) = %d, want 0", len(ciphertextRecords))
	}
	if plaintextRecords[0].Type != protocol.Alert {
		t.Fatalf("plaintextRecords[0].Type = %v, want %v", plaintextRecords[0].Type, protocol.Alert)
	}
}

func buildServerHelloHandshakeMessage() []byte {
	body := buildMinimalServerHelloBody()
	message := make([]byte, protocol.HandshakeHeaderLen+len(body))
	message[0] = byte(protocol.TypeServerHello)
	message[1] = byte(len(body) >> 16)
	message[2] = byte(len(body) >> 8)
	message[3] = byte(len(body))
	copy(message[protocol.HandshakeHeaderLen:], body)
	return message
}

func buildMinimalServerHelloBody() []byte {
	body := make([]byte, 0, 46)
	body = append(body, 0x03, 0x03)                         // legacy_version
	body = append(body, make([]byte, 32)...)                // random
	body = append(body, 0x00)                               // session_id length
	body = append(body, 0x13, 0x01)                         // TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)                               // compression method
	body = append(body, 0x00, 0x06)                         // extensions length
	body = append(body, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions: TLS1.3
	return body
}
