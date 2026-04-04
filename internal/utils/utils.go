package utils

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/alert"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

var ErrServerHelloNotFound = errors.New("tls: server hello not found in records")
var ErrNilAEAD = errors.New("tls: aead is nil")

type AlertRecordError struct {
	Level       protocol.AlertLevel
	Description protocol.AlertDescription
}

func (e *AlertRecordError) Error() string {
	return fmt.Sprintf("tls: received alert: level=%d description=%s", uint8(e.Level), e.Description.String())
}

func GenerateRandom32Bytes() [32]byte {
	var random [32]byte
	_, _ = rand.Read(random[:])
	return random
}

func ParseRecords(data []byte) ([]record.TLSPlaintext, []record.TLSCiphertext, error) {
	allRecords, err := record.ParseTLSPlaintextRecords(data)
	if err != nil {
		return nil, nil, err
	}

	plaintextRecords := make([]record.TLSPlaintext, 0, len(allRecords))
	ciphertextRecords := make([]record.TLSCiphertext, 0, len(allRecords))

	for _, rec := range allRecords {
		if rec.Type == protocol.Alert {
			alertErr := parseAlertRecordError(rec)
			return nil, nil, alertErr
		}

		if rec.Type == protocol.ApplicationData {
			ciphertextRecords = append(ciphertextRecords, rec)
			continue
		}

		plaintextRecords = append(plaintextRecords, rec)
	}

	return plaintextRecords, ciphertextRecords, nil
}

func ParseServerHelloFromBytes(data []byte) (handshake.ServerHello, []record.TLSPlaintext, []record.TLSCiphertext, error) {
	plaintextRecords, ciphertextRecords, err := ParseRecords(data)
	if err != nil {
		return handshake.ServerHello{}, nil, nil, err
	}

	serverHello, err := ParseServerHelloFromRecords(plaintextRecords)
	if err != nil {
		return handshake.ServerHello{}, plaintextRecords, ciphertextRecords, err
	}

	return serverHello, plaintextRecords, ciphertextRecords, nil
}

func ParseServerHelloFromRecords(records []record.TLSPlaintext) (handshake.ServerHello, error) {
	var serverHello handshake.ServerHello

	messages, err := CollectHandshakeMessages(records)
	if err != nil {
		return serverHello, err
	}

	message, ok := FindFirstHandshakeMessage(messages, protocol.TypeServerHello)
	if !ok {
		return serverHello, ErrServerHelloNotFound
	}

	if err := serverHello.Unmarshal(message); err != nil {
		return serverHello, fmt.Errorf("tls: failed to unmarshal server hello: %w", err)
	}

	return serverHello, nil
}

func DecodeTLSCiphertextRecordWithAEAD(rec record.TLSCiphertext, aead cipher.AEAD, iv []byte, seq uint64) ([]byte, protocol.ContentType, error) {
	if rec.Type != protocol.ApplicationData {
		payload := make([]byte, len(rec.Payload))
		copy(payload, rec.Payload)
		return payload, rec.Type, nil
	}

	if aead == nil {
		return nil, 0, ErrNilAEAD
	}
	if len(iv) != aead.NonceSize() {
		return nil, 0, fmt.Errorf("tls: invalid iv length: %d", len(iv))
	}
	if len(rec.Payload) < aead.Overhead() {
		return nil, 0, errors.New("tls: bad record MAC")
	}

	nonce := buildTLS13Nonce(iv, seq)
	plaintext, err := aead.Open(nil, nonce, rec.Payload, rec.Header())
	if err != nil {
		return nil, 0, errors.New("tls: bad record MAC")
	}

	inner, err := record.ParseTLSInnerPlaintext(plaintext)
	if err != nil {
		return nil, 0, errors.New("tls: unexpected message")
	}
	if len(inner.Content) > protocol.MaxPayloadLen {
		return nil, 0, errors.New("tls: record overflow")
	}

	content := make([]byte, len(inner.Content))
	copy(content, inner.Content)
	return content, inner.Type, nil
}

func DecodeTLSCiphertextRecordsWithAEAD(ciphertextRecords []record.TLSCiphertext, aead cipher.AEAD, iv []byte, initialSeq uint64) ([]record.TLSPlaintext, error) {
	plaintextRecords := make([]record.TLSPlaintext, 0, len(ciphertextRecords))
	seq := initialSeq

	for _, rec := range ciphertextRecords {
		content, contentType, err := DecodeTLSCiphertextRecordWithAEAD(rec, aead, iv, seq)
		if err != nil {
			return nil, err
		}

		if rec.Type == protocol.ApplicationData {
			seq++
		}

		plainRec := record.TLSPlaintext{
			Type:    contentType,
			Version: rec.Version,
			Length:  uint16(len(content)),
			Payload: content,
		}

		if plainRec.Type == protocol.Alert {
			return nil, parseAlertRecordError(plainRec)
		}

		plaintextRecords = append(plaintextRecords, plainRec)
	}

	return plaintextRecords, nil
}

func DecodeTLSCiphertextRecordsWithChaCha20Poly1305(ciphertextRecords []record.TLSCiphertext, key []byte, iv []byte, initialSeq uint64) ([]record.TLSPlaintext, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("tls: invalid chacha20-poly1305 key length: %d", len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to create chacha20-poly1305 aead: %w", err)
	}

	return DecodeTLSCiphertextRecordsWithAEAD(ciphertextRecords, aead, iv, initialSeq)
}

func ParseServerTLS13HandshakeMessages(records []record.TLSPlaintext) (*handshake.EncryptedExtensions, *handshake.Certificate, *handshake.CertificateVerify, *handshake.Finished, error) {
	messages, err := CollectHandshakeMessages(records)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var encryptedExtensions *handshake.EncryptedExtensions
	var certificate *handshake.Certificate
	var certificateVerify *handshake.CertificateVerify
	var finished *handshake.Finished

	for _, message := range messages {
		if len(message) < protocol.HandshakeHeaderLen {
			continue
		}

		switch protocol.HandshakeType(message[0]) {
		case protocol.TypeEncryptedExtensions:
			if encryptedExtensions != nil {
				return nil, nil, nil, nil, errors.New("tls: duplicate encrypted_extensions")
			}
			v := &handshake.EncryptedExtensions{}
			if err := v.Unmarshal(message); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("tls: failed to parse encrypted_extensions: %w", err)
			}
			encryptedExtensions = v

		case protocol.TypeCertificate:
			if certificate != nil {
				return nil, nil, nil, nil, errors.New("tls: duplicate certificate")
			}
			v := &handshake.Certificate{}
			if err := v.Unmarshal(message); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("tls: failed to parse certificate: %w", err)
			}
			certificate = v

		case protocol.TypeCertificateVerify:
			if certificateVerify != nil {
				return nil, nil, nil, nil, errors.New("tls: duplicate certificate_verify")
			}
			v := &handshake.CertificateVerify{}
			if err := v.Unmarshal(message); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("tls: failed to parse certificate_verify: %w", err)
			}
			certificateVerify = v

		case protocol.TypeFinished:
			if finished != nil {
				return nil, nil, nil, nil, errors.New("tls: duplicate finished")
			}
			v := &handshake.Finished{}
			if err := v.Unmarshal(message); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("tls: failed to parse finished: %w", err)
			}
			finished = v
		}
	}

	return encryptedExtensions, certificate, certificateVerify, finished, nil
}

func DecodeAndParseServerTLS13HandshakeMessagesWithAEAD(ciphertextRecords []record.TLSCiphertext, aead cipher.AEAD, iv []byte, initialSeq uint64) (*handshake.EncryptedExtensions, *handshake.Certificate, *handshake.CertificateVerify, *handshake.Finished, []record.TLSPlaintext, error) {
	plaintextRecords, err := DecodeTLSCiphertextRecordsWithAEAD(ciphertextRecords, aead, iv, initialSeq)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	encryptedExtensions, certificate, certificateVerify, finished, err := ParseServerTLS13HandshakeMessages(plaintextRecords)
	if err != nil {
		return nil, nil, nil, nil, plaintextRecords, err
	}

	return encryptedExtensions, certificate, certificateVerify, finished, plaintextRecords, nil
}

func CollectHandshakeMessages(records []record.TLSPlaintext) ([][]byte, error) {
	stream := make([]byte, 0)
	messages := make([][]byte, 0)

	for _, rec := range records {
		if rec.Type != protocol.Handshake {
			continue
		}

		stream = append(stream, rec.Payload...)

		for len(stream) >= protocol.HandshakeHeaderLen {
			msgLen := parseUint24(stream[1:protocol.HandshakeHeaderLen])
			msgTotalLen := protocol.HandshakeHeaderLen + msgLen
			if msgTotalLen <= protocol.HandshakeHeaderLen {
				return nil, fmt.Errorf("tls: malformed handshake length %d", msgLen)
			}

			if len(stream) < msgTotalLen {
				break
			}

			message := make([]byte, msgTotalLen)
			copy(message, stream[:msgTotalLen])
			messages = append(messages, message)
			stream = stream[msgTotalLen:]
		}
	}

	if len(stream) > 0 {
		if len(stream) < protocol.HandshakeHeaderLen {
			return nil, fmt.Errorf("tls: incomplete handshake header (have=%d)", len(stream))
		}
		msgLen := parseUint24(stream[1:protocol.HandshakeHeaderLen])
		msgTotalLen := protocol.HandshakeHeaderLen + msgLen
		return nil, fmt.Errorf("tls: incomplete handshake message (need=%d, have=%d)", msgTotalLen, len(stream))
	}

	return messages, nil
}

func FindFirstHandshakeMessage(messages [][]byte, typ protocol.HandshakeType) ([]byte, bool) {
	for _, message := range messages {
		if len(message) < protocol.HandshakeHeaderLen {
			continue
		}
		if protocol.HandshakeType(message[0]) != typ {
			continue
		}

		result := make([]byte, len(message))
		copy(result, message)
		return result, true
	}

	return nil, false
}

func parseAlertRecordError(rec record.TLSPlaintext) error {
	alertMessage := &alert.Alert{}
	if err := alertMessage.Unmarshal(rec.Payload); err != nil {
		return fmt.Errorf("tls: received malformed alert record: %w", err)
	}

	return &AlertRecordError{
		Level:       alertMessage.Level,
		Description: alertMessage.Description,
	}
}

func parseUint24(data []byte) int {
	return int(data[0])<<16 | int(data[1])<<8 | int(data[2])
}

func buildTLS13Nonce(iv []byte, seq uint64) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)

	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(seq)
		seq >>= 8
	}

	return nonce
}
