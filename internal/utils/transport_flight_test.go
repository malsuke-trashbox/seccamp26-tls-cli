package utils

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func mustHandshakeRecord(t *testing.T, payload []byte) []byte {
	t.Helper()
	rec, err := record.NewTLSPlaintext(protocol.Handshake, payload)
	if err != nil {
		t.Fatalf("NewTLSPlaintext() failed: %v", err)
	}
	return rec.Marshal()
}

// fullRecordsReceived reports the flight complete once buf parses into at least
// want complete records with no trailing partial record.
func fullRecordsReceived(want int) func([]byte) bool {
	return func(buf []byte) bool {
		records, rest, err := record.ParseTLSPlaintextRecordsWithRemainder(buf)
		return err == nil && len(rest) == 0 && len(records) >= want
	}
}

// TestReadServerHandshakeFlight_AccumulatesAcrossReads verifies the core fix:
// a flight delivered over multiple Read calls is accumulated, not truncated to
// whatever the first Read returned.
func TestReadServerHandshakeFlight_AccumulatesAcrossReads(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	rec1 := mustHandshakeRecord(t, bytes.Repeat([]byte{0xAA}, 64))
	rec2 := mustHandshakeRecord(t, bytes.Repeat([]byte{0xBB}, 64))

	writeErrCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		if _, err := serverConn.Write(rec1); err != nil {
			writeErrCh <- err
			return
		}
		if _, err := serverConn.Write(rec2); err != nil {
			writeErrCh <- err
			return
		}
		writeErrCh <- nil
	}()

	got, err := ReadServerHandshakeFlight(clientConn, fullRecordsReceived(2))
	if err != nil {
		t.Fatalf("ReadServerHandshakeFlight() failed: %v", err)
	}

	want := append(append([]byte{}, rec1...), rec2...)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d bytes (flight not fully accumulated)", len(got), len(want))
	}
	if writeErr := <-writeErrCh; writeErr != nil {
		t.Fatalf("writer failed: %v", writeErr)
	}
}

// TestReadServerHandshakeFlight_ReassemblesSplitRecord verifies a single record
// split across TCP segments (here: header split from body) is reassembled.
func TestReadServerHandshakeFlight_ReassemblesSplitRecord(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	full := mustHandshakeRecord(t, bytes.Repeat([]byte{0xCC}, 128))

	writeErrCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		if _, err := serverConn.Write(full[:3]); err != nil {
			writeErrCh <- err
			return
		}
		if _, err := serverConn.Write(full[3:]); err != nil {
			writeErrCh <- err
			return
		}
		writeErrCh <- nil
	}()

	got, err := ReadServerHandshakeFlight(clientConn, fullRecordsReceived(1))
	if err != nil {
		t.Fatalf("ReadServerHandshakeFlight() failed: %v", err)
	}
	if !bytes.Equal(got, full) {
		t.Fatalf("got %d bytes, want %d bytes (split record not reassembled)", len(got), len(full))
	}
	if writeErr := <-writeErrCh; writeErr != nil {
		t.Fatalf("writer failed: %v", writeErr)
	}
}

// TestReadServerHandshakeFlight_Alert verifies an alert record aborts the read.
func TestReadServerHandshakeFlight_Alert(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	alertRec, err := record.NewTLSPlaintext(protocol.Alert, []byte{byte(protocol.AlertLevelFatal), byte(protocol.AlertUnexpectedMessage)})
	if err != nil {
		t.Fatalf("NewTLSPlaintext() failed: %v", err)
	}

	go func() {
		defer serverConn.Close()
		_, _ = serverConn.Write(alertRec.Marshal())
	}()

	_, err = ReadServerHandshakeFlight(clientConn, func([]byte) bool { return false })
	if !errors.Is(err, ErrAlertReceived) {
		t.Fatalf("err = %v, want ErrAlertReceived", err)
	}
}
