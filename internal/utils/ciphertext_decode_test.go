package utils

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestDecodeTLSCiphertextRecordsWithAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, chacha20poly1305.KeySize)
	iv := bytes.Repeat([]byte{0x22}, chacha20poly1305.NonceSize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	encryptedExtensionsMsg := buildHandshakeMessage(protocol.TypeEncryptedExtensions, []byte{0x00, 0x00})
	rec := encryptAsApplicationDataCiphertext(t, aead, iv, 0, encryptedExtensionsMsg, protocol.Handshake)

	plaintextRecords, err := DecodeTLSCiphertextRecordsWithAEAD([]record.TLSCiphertext{rec}, aead, iv, 0)
	if err != nil {
		t.Fatalf("DecodeTLSCiphertextRecordsWithAEAD() failed: %v", err)
	}
	if len(plaintextRecords) != 1 {
		t.Fatalf("len(plaintextRecords) = %d, want 1", len(plaintextRecords))
	}
	if plaintextRecords[0].Type != protocol.Handshake {
		t.Fatalf("plaintextRecords[0].Type = %v, want %v", plaintextRecords[0].Type, protocol.Handshake)
	}
	if !bytes.Equal(plaintextRecords[0].Payload, encryptedExtensionsMsg) {
		t.Fatalf("payload mismatch: got=%x want=%x", plaintextRecords[0].Payload, encryptedExtensionsMsg)
	}
}

func TestDecodeTLSCiphertextRecordsWithAEADAlert(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, chacha20poly1305.KeySize)
	iv := bytes.Repeat([]byte{0x22}, chacha20poly1305.NonceSize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	rec := encryptAsApplicationDataCiphertext(
		t,
		aead,
		iv,
		0,
		[]byte{0x02, byte(protocol.AlertHandshakeFailure)},
		protocol.Alert,
	)

	_, err = DecodeTLSCiphertextRecordsWithAEAD([]record.TLSCiphertext{rec}, aead, iv, 0)
	if err == nil {
		t.Fatal("DecodeTLSCiphertextRecordsWithAEAD() should fail on alert")
	}
	if _, ok := err.(*AlertRecordError); !ok {
		t.Fatalf("error = %T, want *AlertRecordError", err)
	}
}

func TestDecodeAndParseServerTLS13HandshakeMessagesWithAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, chacha20poly1305.KeySize)
	iv := bytes.Repeat([]byte{0x44}, chacha20poly1305.NonceSize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	messages := [][]byte{
		buildHandshakeMessage(protocol.TypeEncryptedExtensions, []byte{0x00, 0x00}),
		buildHandshakeMessage(protocol.TypeCertificate, []byte{0x00, 0x00, 0x00, 0x00}),
		buildHandshakeMessage(protocol.TypeCertificateVerify, []byte{0x08, 0x07, 0x00, 0x01, 0xaa}),
		buildHandshakeMessage(protocol.TypeFinished, []byte{0xde, 0xad}),
	}

	ciphertextRecords := make([]record.TLSCiphertext, 0, len(messages))
	for i, message := range messages {
		rec := encryptAsApplicationDataCiphertext(t, aead, iv, uint64(i), message, protocol.Handshake)
		ciphertextRecords = append(ciphertextRecords, rec)
	}

	encryptedExtensions, certificate, certificateVerify, finished, plaintextRecords, err := DecodeAndParseServerTLS13HandshakeMessagesWithAEAD(ciphertextRecords, aead, iv, 0)
	if err != nil {
		t.Fatalf("DecodeAndParseServerTLS13HandshakeMessagesWithAEAD() failed: %v", err)
	}

	if len(plaintextRecords) != 4 {
		t.Fatalf("len(plaintextRecords) = %d, want 4", len(plaintextRecords))
	}
	if encryptedExtensions == nil {
		t.Fatal("encryptedExtensions should not be nil")
	}
	if certificate == nil {
		t.Fatal("certificate should not be nil")
	}
	if certificateVerify == nil {
		t.Fatal("certificateVerify should not be nil")
	}
	if finished == nil {
		t.Fatal("finished should not be nil")
	}

	if certificateVerify.SignatureAlgorithm != protocol.Ed25519 {
		t.Fatalf("certificateVerify.SignatureAlgorithm = %v, want %v", certificateVerify.SignatureAlgorithm, protocol.Ed25519)
	}
	if len(finished.VerifyData) != 2 {
		t.Fatalf("len(finished.VerifyData) = %d, want 2", len(finished.VerifyData))
	}
}

func buildHandshakeMessage(msgType protocol.HandshakeType, body []byte) []byte {
	message := make([]byte, 0, protocol.HandshakeHeaderLen+len(body))
	message = append(message, byte(msgType))
	message = append(message, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	message = append(message, body...)
	return message
}

func encryptAsApplicationDataCiphertext(t *testing.T, aead cipher.AEAD, iv []byte, seq uint64, content []byte, contentType protocol.ContentType) record.TLSCiphertext {
	t.Helper()

	inner := (&record.TLSInnerPlaintext{
		Content: content,
		Type:    contentType,
	}).Marshal()

	rec := record.TLSCiphertext{
		Type:    protocol.ApplicationData,
		Version: protocol.TLS_VERSION_1_2,
		Length:  uint16(len(inner) + aead.Overhead()),
		Payload: make([]byte, len(inner)+aead.Overhead()),
	}

	nonce := buildTLS13Nonce(iv, seq)
	aead.Seal(rec.Payload[:0], nonce, inner, rec.Header())
	return rec
}
