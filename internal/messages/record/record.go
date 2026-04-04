package record

import (
	"errors"
	"fmt"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrPayloadTooLarge        = errors.New("tls: payload too large")
	ErrDataTooShort           = errors.New("tls: data too short")
	ErrDataLengthMismatch     = errors.New("tls: data length mismatch")
	ErrInnerPlaintextTooShort = errors.New("tls: inner plaintext too short")
	ErrInnerPlaintextNoType   = errors.New("tls: inner plaintext missing content type")
)

/**
 * TLSPlaintext record.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
 */
type TLSPlaintext struct {
	Type    protocol.ContentType
	Version protocol.TLSVersion
	Length  uint16
	Payload []byte
}

// TLSCiphertext shares the same wire layout and methods as TLSPlaintext.
// The name is used to distinguish semantic intent at the call site.
type TLSCiphertext = TLSPlaintext

/**
 * TLSInnerPlaintext structure.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
 *
 * struct {
 *     opaque content[TLSPlaintext.length];
 *     ContentType type;
 *     uint8 zeros[length_of_padding];
 * } TLSInnerPlaintext;
 */
type TLSInnerPlaintext struct {
	Content []byte
	Type    protocol.ContentType
	Padding []byte
}

func NewTLSPlaintext(contentType protocol.ContentType, fragment []byte) (*TLSPlaintext, error) {
	if len(fragment) > protocol.MaxPayloadLen {
		return nil, ErrPayloadTooLarge
	}

	return &TLSPlaintext{
		Type:    contentType,
		Version: protocol.TLS_VERSION_1_2, // TLS 1.3 uses 0x0303 for compatibility
		Length:  uint16(len(fragment)),
		Payload: fragment,
	}, nil
}

func (p *TLSInnerPlaintext) Marshal() []byte {
	buf := make([]byte, 0, len(p.Content)+1+len(p.Padding))
	buf = append(buf, p.Content...)
	buf = append(buf, byte(p.Type))
	if len(p.Padding) > 0 {
		buf = append(buf, p.Padding...)
	}
	return buf
}

func ParseTLSInnerPlaintext(data []byte) (*TLSInnerPlaintext, error) {
	if len(data) < 1 {
		return nil, ErrInnerPlaintextTooShort
	}

	typeIndex := -1
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			typeIndex = i
			break
		}
	}

	if typeIndex < 0 {
		return nil, ErrInnerPlaintextNoType
	}

	content := make([]byte, typeIndex)
	copy(content, data[:typeIndex])

	padding := make([]byte, len(data)-typeIndex-1)
	copy(padding, data[typeIndex+1:])

	return &TLSInnerPlaintext{
		Content: content,
		Type:    protocol.ContentType(data[typeIndex]),
		Padding: padding,
	}, nil
}

func (r *TLSPlaintext) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(uint8(r.Type))
	b.AddUint16(uint16(r.Version))
	b.AddUint16(r.Length)
	b.AddBytes(r.Payload)
	result, _ := b.Bytes()
	return result
}

func (r *TLSPlaintext) Header() []byte {
	header := make([]byte, protocol.RecordHeaderLen)
	header[0] = byte(r.Type)
	header[1] = byte(r.Version >> 8)
	header[2] = byte(r.Version)
	header[3] = byte(r.Length >> 8)
	header[4] = byte(r.Length)
	return header
}

func ParseTLSPlaintext(data []byte) (*TLSPlaintext, error) {
	s := cryptobyte.String(data)

	var typ uint8
	var version uint16
	var length uint16

	if !s.ReadUint8(&typ) {
		return nil, ErrDataTooShort
	}
	if !s.ReadUint16(&version) {
		return nil, ErrDataTooShort
	}
	if !s.ReadUint16(&length) {
		return nil, ErrDataTooShort
	}

	if len(s) < int(length) {
		return nil, ErrDataLengthMismatch
	}

	payload := make([]byte, length)
	copy(payload, s[:length])

	return &TLSPlaintext{
		Type:    protocol.ContentType(typ),
		Version: protocol.TLSVersion(version),
		Length:  length,
		Payload: payload,
	}, nil
}

func ParseTLSPlaintextHeader(data []byte) (*TLSPlaintext, error) {
	if len(data) < protocol.RecordHeaderLen {
		return nil, ErrDataTooShort
	}

	s := cryptobyte.String(data[:protocol.RecordHeaderLen])

	var typ uint8
	var version uint16
	var length uint16

	if !s.ReadUint8(&typ) || !s.ReadUint16(&version) || !s.ReadUint16(&length) {
		return nil, ErrDataTooShort
	}

	return &TLSPlaintext{
		Type:    protocol.ContentType(typ),
		Version: protocol.TLSVersion(version),
		Length:  length,
	}, nil
}

func ParseTLSPlaintextRecords(data []byte) ([]TLSPlaintext, error) {
	records, remain, err := ParseTLSPlaintextRecordsWithRemainder(data)
	if err != nil {
		return nil, err
	}
	if len(remain) > 0 {
		return nil, fmt.Errorf("tls: incomplete record fragment: %d bytes", len(remain))
	}
	return records, nil
}

func ParseTLSPlaintextRecordsWithRemainder(data []byte) ([]TLSPlaintext, []byte, error) {
	if len(data) == 0 {
		return nil, nil, ErrDataTooShort
	}

	records := make([]TLSPlaintext, 0)
	offset := 0

	for {
		remaining := len(data) - offset
		if remaining == 0 {
			return records, nil, nil
		}

		if remaining < protocol.RecordHeaderLen {
			rest := append([]byte(nil), data[offset:]...)
			return records, rest, nil
		}

		hdr, err := ParseTLSPlaintextHeader(data[offset : offset+protocol.RecordHeaderLen])
		if err != nil {
			return nil, nil, fmt.Errorf("tls: failed to parse record header at offset %d: %w", offset, err)
		}

		recordLen := protocol.RecordHeaderLen + int(hdr.Length)
		if remaining < recordLen {
			rest := append([]byte(nil), data[offset:]...)
			return records, rest, nil
		}

		rec, err := ParseTLSPlaintext(data[offset : offset+recordLen])
		if err != nil {
			return nil, nil, fmt.Errorf("tls: failed to parse record at offset %d: %w", offset, err)
		}

		records = append(records, *rec)
		offset += recordLen
	}
}

func ParseTLSCiphertextRecords(data []byte) ([]TLSCiphertext, error) {
	plaintextRecords, err := ParseTLSPlaintextRecords(data)
	if err != nil {
		return nil, err
	}

	ciphertextRecords := make([]TLSCiphertext, len(plaintextRecords))
	copy(ciphertextRecords, plaintextRecords)
	return ciphertextRecords, nil
}
