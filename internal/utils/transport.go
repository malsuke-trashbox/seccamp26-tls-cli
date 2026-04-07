package utils

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/appdata"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

const chacha20poly1305TagSize = 16

func ConcatHandshakeMessages(records []record.TLSPlaintext) ([]byte, error) {
	messages, err := CollectHandshakeMessages(records)
	if err != nil {
		return nil, err
	}

	totalLen := 0
	for _, message := range messages {
		totalLen += len(message)
	}

	result := make([]byte, 0, totalLen)
	for _, message := range messages {
		result = append(result, message...)
	}

	return result, nil
}

func BuildTLSInnerPlaintext(innerType protocol.ContentType, innerContent []byte) []byte {
	return (&record.TLSInnerPlaintext{
		Content: innerContent,
		Type:    innerType,
	}).Marshal()
}

func NewTLS13ApplicationDataCiphertextRecord(ciphertextPayloadLen int) record.TLSCiphertext {
	return record.TLSCiphertext{
		Type:    protocol.ApplicationData,
		Version: protocol.TLS_VERSION_1_2,
		Length:  uint16(ciphertextPayloadLen),
		Payload: make([]byte, ciphertextPayloadLen),
	}
}

func NewTLS13ApplicationDataCiphertextRecordForInnerPlaintext(innerPlaintext []byte) record.TLSCiphertext {
	return NewTLS13ApplicationDataCiphertextRecord(len(innerPlaintext) + chacha20poly1305TagSize)
}

func EncryptTLS13RecordPayload(key []byte, iv []byte, seq uint64, additionalData []byte, innerPlaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, len(innerPlaintext)+aead.Overhead())
	nonce := buildTLS13Nonce(iv, seq)
	aead.Seal(payload[:0], nonce, innerPlaintext, additionalData)
	return payload, nil
}

func EncryptTLS13Record(key []byte, iv []byte, seq uint64, innerType protocol.ContentType, innerContent []byte) (record.TLSCiphertext, error) {
	innerPlaintext := BuildTLSInnerPlaintext(innerType, innerContent)
	ciphertextRecord := NewTLS13ApplicationDataCiphertextRecordForInnerPlaintext(innerPlaintext)

	payload, err := EncryptTLS13RecordPayload(key, iv, seq, ciphertextRecord.Header(), innerPlaintext)
	if err != nil {
		return record.TLSCiphertext{}, err
	}

	ciphertextRecord.Payload = payload
	ciphertextRecord.Length = uint16(len(payload))
	return ciphertextRecord, nil
}

func ExtractApplicationDataCiphertextRecords(records []record.TLSPlaintext) []record.TLSCiphertext {
	ciphertextRecords := make([]record.TLSCiphertext, 0, len(records))
	for _, rec := range records {
		if rec.Type == protocol.ApplicationData {
			ciphertextRecords = append(ciphertextRecords, rec)
		}
	}

	return ciphertextRecords
}

func DecodeApplicationDataFromCiphertextRecords(ciphertextRecords []record.TLSCiphertext, serverAppKey []byte, serverAppIV []byte, initialSeq uint64) ([]byte, uint64, error) {
	decodedRecords, nextSeq, err := DecodeTLSCiphertextRecordsWithChaCha20Poly1305AndNextSeq(ciphertextRecords, serverAppKey, serverAppIV, initialSeq)
	if err != nil {
		return nil, nextSeq, err
	}

	decoded, err := CollectApplicationDataFromPlaintextRecords(decodedRecords)
	if err != nil {
		return nil, nextSeq, err
	}
	return decoded, nextSeq, nil
}

func DecodeTLSCiphertextRecordsWithChaCha20Poly1305AndNextSeq(ciphertextRecords []record.TLSCiphertext, key []byte, iv []byte, initialSeq uint64) ([]record.TLSPlaintext, uint64, error) {
	seq := initialSeq
	decodedRecords := make([]record.TLSPlaintext, 0, len(ciphertextRecords))

	for _, ciphertextRecord := range ciphertextRecords {
		plaintextRecords, decodeErr := DecodeTLSCiphertextRecordsWithChaCha20Poly1305(
			[]record.TLSCiphertext{ciphertextRecord},
			key,
			iv,
			seq,
		)
		if ciphertextRecord.Type == protocol.ApplicationData {
			seq++
		}

		if decodeErr != nil {
			return nil, seq, decodeErr
		}

		decodedRecords = append(decodedRecords, plaintextRecords...)
	}

	return decodedRecords, seq, nil
}

func CollectApplicationDataFromPlaintextRecords(records []record.TLSPlaintext) ([]byte, error) {
	collected := make([]byte, 0)

	for _, rec := range records {
		if rec.Type != protocol.ApplicationData {
			continue
		}

		app := &appdata.ApplicationData{}
		if err := app.Unmarshal(rec.Payload); err != nil {
			return nil, err
		}
		collected = append(collected, app.Data...)
	}

	return collected, nil
}

func ReadServerApplicationData(conn net.Conn, serverAppKey []byte, serverAppIV []byte) ([]byte, []record.TLSPlaintext, error) {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	remainder := make([]byte, 0)
	seq := uint64(0)
	collected := make([]byte, 0)
	decodedRecords := make([]record.TLSPlaintext, 0)
	buf := make([]byte, 8192)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := append(append([]byte{}, remainder...), buf[:n]...)
			records, rest, parseErr := record.ParseTLSPlaintextRecordsWithRemainder(chunk)
			if parseErr != nil {
				return nil, nil, parseErr
			}
			remainder = rest

			ciphertextRecords := ExtractApplicationDataCiphertextRecords(records)

			if len(ciphertextRecords) > 0 {
				decodedBatch, nextSeq, decodeErr := DecodeTLSCiphertextRecordsWithChaCha20Poly1305AndNextSeq(ciphertextRecords, serverAppKey, serverAppIV, seq)
				seq = nextSeq
				if decodeErr != nil {
					return nil, nil, decodeErr
				}

				decodedRecords = append(decodedRecords, decodedBatch...)

				decoded, collectErr := CollectApplicationDataFromPlaintextRecords(decodedBatch)
				if collectErr != nil {
					return nil, nil, collectErr
				}

				if len(decoded) > 0 {
					collected = append(collected, decoded...)
				}
			}
		}

		if err == nil {
			continue
		}

		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if len(collected) > 0 || len(decodedRecords) > 0 {
				return collected, decodedRecords, nil
			}
			return nil, nil, err
		}

		if errors.Is(err, io.EOF) {
			if len(collected) > 0 || len(decodedRecords) > 0 {
				return collected, decodedRecords, nil
			}
			return nil, nil, err
		}

		return nil, nil, err
	}
}
