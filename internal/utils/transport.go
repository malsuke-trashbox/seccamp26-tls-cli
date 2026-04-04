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

func EncryptTLS13Record(key []byte, iv []byte, seq uint64, innerType protocol.ContentType, innerContent []byte) (record.TLSCiphertext, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return record.TLSCiphertext{}, err
	}

	innerPlaintext := (&record.TLSInnerPlaintext{
		Content: innerContent,
		Type:    innerType,
	}).Marshal()

	ciphertextLen := len(innerPlaintext) + aead.Overhead()
	ciphertextRecord := record.TLSCiphertext{
		Type:    protocol.ApplicationData,
		Version: protocol.TLS_VERSION_1_2,
		Length:  uint16(ciphertextLen),
		Payload: make([]byte, ciphertextLen),
	}

	nonce := buildTLS13Nonce(iv, seq)
	aead.Seal(ciphertextRecord.Payload[:0], nonce, innerPlaintext, ciphertextRecord.Header())
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
	decoded, nextSeq, _, err := decodeApplicationDataFromCiphertextRecords(ciphertextRecords, serverAppKey, serverAppIV, initialSeq)
	if err != nil {
		return nil, nextSeq, err
	}
	return decoded, nextSeq, nil
}

func decodeApplicationDataFromCiphertextRecords(ciphertextRecords []record.TLSCiphertext, serverAppKey []byte, serverAppIV []byte, initialSeq uint64) ([]byte, uint64, bool, error) {
	seq := initialSeq
	collected := make([]byte, 0)

	for _, ciphertextRecord := range ciphertextRecords {
		plaintextRecords, decodeErr := DecodeTLSCiphertextRecordsWithChaCha20Poly1305(
			[]record.TLSCiphertext{ciphertextRecord},
			serverAppKey,
			serverAppIV,
			seq,
		)
		seq++

		if decodeErr != nil {
			var alertErr *AlertRecordError
			if errors.As(decodeErr, &alertErr) && alertErr.Description == protocol.AlertCloseNotify {
				return collected, seq, true, nil
			}
			return nil, seq, false, decodeErr
		}

		for _, rec := range plaintextRecords {
			if rec.Type != protocol.ApplicationData {
				continue
			}

			app := &appdata.ApplicationData{}
			if unmarshalErr := app.Unmarshal(rec.Payload); unmarshalErr != nil {
				return nil, seq, false, unmarshalErr
			}
			collected = append(collected, app.Data...)
		}
	}

	return collected, seq, false, nil
}

func ReadServerApplicationData(conn net.Conn, serverAppKey []byte, serverAppIV []byte) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	remainder := make([]byte, 0)
	seq := uint64(0)
	collected := make([]byte, 0)
	buf := make([]byte, 8192)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := append(append([]byte{}, remainder...), buf[:n]...)
			records, rest, parseErr := record.ParseTLSPlaintextRecordsWithRemainder(chunk)
			if parseErr != nil {
				return nil, parseErr
			}
			remainder = rest

			ciphertextRecords := ExtractApplicationDataCiphertextRecords(records)

			if len(ciphertextRecords) > 0 {
				decoded, nextSeq, closeNotify, decodeErr := decodeApplicationDataFromCiphertextRecords(ciphertextRecords, serverAppKey, serverAppIV, seq)
				seq = nextSeq
				if decodeErr != nil {
					return nil, decodeErr
				}

				if len(decoded) > 0 {
					collected = append(collected, decoded...)
				}

				if closeNotify {
					if len(collected) > 0 {
						return collected, nil
					}
					return nil, nil
				}
			}
		}

		if err == nil {
			continue
		}

		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if len(collected) > 0 {
				return collected, nil
			}
			return nil, err
		}

		if errors.Is(err, io.EOF) {
			if len(collected) > 0 {
				return collected, nil
			}
			return nil, err
		}

		return nil, err
	}
}
