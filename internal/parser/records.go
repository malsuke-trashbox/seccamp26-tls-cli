package parser

import (
	"errors"
	"fmt"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

var (
	ErrNoDataToParse       = errors.New("tls: no data to parse")
	ErrServerHelloNotFound = errors.New("tls: server hello not found in parsed records")
)

// ParseTLSRecords parses a contiguous byte stream into TLS records.
func ParseTLSRecords(data []byte) ([]record.TLSPlaintext, error) {
	if len(data) == 0 {
		return nil, ErrNoDataToParse
	}

	records := make([]record.TLSPlaintext, 0)
	for offset := 0; offset < len(data); {
		remaining := len(data) - offset
		if remaining < protocol.RecordHeaderLen {
			return records, fmt.Errorf("tls: short record header at offset %d (remaining=%d)", offset, remaining)
		}

		hdr, err := record.ParseTLSPlaintextHeader(data[offset : offset+protocol.RecordHeaderLen])
		if err != nil {
			return records, fmt.Errorf("tls: failed to parse record header at offset %d: %w", offset, err)
		}

		recordLen := protocol.RecordHeaderLen + int(hdr.Length)
		if remaining < recordLen {
			return records, fmt.Errorf("tls: short record body at offset %d (need=%d, remaining=%d)", offset, recordLen, remaining)
		}

		rec, err := record.ParseTLSPlaintext(data[offset : offset+recordLen])
		if err != nil {
			return records, fmt.Errorf("tls: failed to parse record at offset %d: %w", offset, err)
		}

		records = append(records, *rec)
		offset += recordLen
	}

	return records, nil
}

// CollectHandshakeMessages reconstructs handshake messages from handshake records.
func CollectHandshakeMessages(records []record.TLSPlaintext) ([][]byte, error) {
	stream := make([]byte, 0)
	messages := make([][]byte, 0)

	for _, rec := range records {
		if rec.Type != protocol.Handshake {
			continue
		}

		stream = append(stream, rec.Payload...)

		parsed, rest, err := splitHandshakeMessages(stream)
		if err != nil {
			return messages, err
		}
		messages = append(messages, parsed...)
		stream = rest
	}

	if len(stream) > 0 {
		if len(stream) < protocol.HandshakeHeaderLen {
			return messages, fmt.Errorf("tls: incomplete handshake header (have=%d)", len(stream))
		}
		msgLen := parseUint24(stream[1:protocol.HandshakeHeaderLen])
		msgTotalLen := protocol.HandshakeHeaderLen + msgLen
		return messages, fmt.Errorf("tls: incomplete handshake message (need=%d, have=%d)", msgTotalLen, len(stream))
	}

	return messages, nil
}

// FindFirstHandshakeMessage returns the first handshake message matching typ.
func FindFirstHandshakeMessage(messages [][]byte, typ protocol.HandshakeType) ([]byte, bool) {
	for _, message := range messages {
		if len(message) < protocol.HandshakeHeaderLen {
			continue
		}
		if protocol.HandshakeType(message[0]) != typ {
			continue
		}
		copied := make([]byte, len(message))
		copy(copied, message)
		return copied, true
	}
	return nil, false
}

// ParseServerHelloFromMessages parses ServerHello from handshake message list.
func ParseServerHelloFromMessages(messages [][]byte) (handshake.ServerHello, error) {
	var serverHello handshake.ServerHello

	message, ok := FindFirstHandshakeMessage(messages, protocol.TypeServerHello)
	if !ok {
		return serverHello, ErrServerHelloNotFound
	}

	if err := serverHello.Unmarshal(message); err != nil {
		return serverHello, fmt.Errorf("tls: failed to unmarshal server hello: %w", err)
	}

	return serverHello, nil
}

// ParseServerHelloFromRecords parses ServerHello from parsed records.
func ParseServerHelloFromRecords(records []record.TLSPlaintext) (handshake.ServerHello, error) {
	messages, err := CollectHandshakeMessages(records)
	if err != nil {
		return handshake.ServerHello{}, err
	}
	return ParseServerHelloFromMessages(messages)
}

// ParseServerHelloFromBytes parses both records and ServerHello from raw bytes.
func ParseServerHelloFromBytes(data []byte) (handshake.ServerHello, []record.TLSPlaintext, error) {
	records, err := ParseTLSRecords(data)
	if err != nil {
		return handshake.ServerHello{}, nil, err
	}

	serverHello, err := ParseServerHelloFromRecords(records)
	if err != nil {
		return handshake.ServerHello{}, records, err
	}

	return serverHello, records, nil
}

// FilterRecordsByType returns records with a specific content type.
func FilterRecordsByType(records []record.TLSPlaintext, contentType protocol.ContentType) []record.TLSPlaintext {
	filtered := make([]record.TLSPlaintext, 0)
	for _, rec := range records {
		if rec.Type != contentType {
			continue
		}
		copied := record.TLSPlaintext{
			Type:    rec.Type,
			Version: rec.Version,
			Length:  rec.Length,
			Payload: append([]byte(nil), rec.Payload...),
		}
		filtered = append(filtered, copied)
	}
	return filtered
}

// CountRecordTypes counts records by TLS content type.
func CountRecordTypes(records []record.TLSPlaintext) map[protocol.ContentType]int {
	counts := make(map[protocol.ContentType]int)
	for _, rec := range records {
		counts[rec.Type]++
	}
	return counts
}

// DescribeRecord returns a human-readable one-line summary of a record.
func DescribeRecord(rec record.TLSPlaintext) string {
	return fmt.Sprintf(
		"type=%s(0x%02x) version=%s(0x%04x) length=%d payloadLen=%d",
		contentTypeString(rec.Type),
		uint8(rec.Type),
		rec.Version.String(),
		uint16(rec.Version),
		rec.Length,
		len(rec.Payload),
	)
}

// DescribeRecords returns summaries for each record.
func DescribeRecords(records []record.TLSPlaintext) []string {
	lines := make([]string, len(records))
	for i, rec := range records {
		lines[i] = DescribeRecord(rec)
	}
	return lines
}

func splitHandshakeMessages(stream []byte) ([][]byte, []byte, error) {
	messages := make([][]byte, 0)
	offset := 0

	for len(stream)-offset >= protocol.HandshakeHeaderLen {
		msgLen := parseUint24(stream[offset+1 : offset+protocol.HandshakeHeaderLen])
		msgTotalLen := protocol.HandshakeHeaderLen + msgLen

		if len(stream)-offset < msgTotalLen {
			break
		}

		message := make([]byte, msgTotalLen)
		copy(message, stream[offset:offset+msgTotalLen])
		messages = append(messages, message)
		offset += msgTotalLen
	}

	rest := append([]byte(nil), stream[offset:]...)
	return messages, rest, nil
}

func parseUint24(data []byte) int {
	return int(data[0])<<16 | int(data[1])<<8 | int(data[2])
}

func contentTypeString(contentType protocol.ContentType) string {
	switch contentType {
	case protocol.Invalid:
		return "Invalid"
	case protocol.ChangeCipherSpec:
		return "ChangeCipherSpec"
	case protocol.Alert:
		return "Alert"
	case protocol.Handshake:
		return "Handshake"
	case protocol.ApplicationData:
		return "ApplicationData"
	default:
		return "Unknown"
	}
}
