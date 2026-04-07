package utils

import (
	"bytes"
	"net"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/appdata"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestReadServerApplicationData_CloseNotifyAfterData(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, chacha20poly1305.KeySize)
	iv := bytes.Repeat([]byte{0x22}, chacha20poly1305.NonceSize)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	writeErrCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()

		payload := (&appdata.ApplicationData{Data: []byte("hello")}).Marshal()
		rec, err := EncryptTLS13Record(key, iv, 0, protocol.ApplicationData, payload)
		if err != nil {
			writeErrCh <- err
			return
		}
		if _, err := serverConn.Write(rec.Marshal()); err != nil {
			writeErrCh <- err
			return
		}

		alertPayload := []byte{byte(protocol.AlertLevelWarning), byte(protocol.AlertCloseNotify)}
		alertRec, err := EncryptTLS13Record(key, iv, 1, protocol.Alert, alertPayload)
		if err != nil {
			writeErrCh <- err
			return
		}
		if _, err := serverConn.Write(alertRec.Marshal()); err != nil {
			writeErrCh <- err
			return
		}

		writeErrCh <- nil
	}()

	got, decodedRecords, err := ReadServerApplicationData(clientConn, key, iv)
	if err != nil {
		t.Fatalf("ReadServerApplicationData() failed: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("got=%q, want=%q", got, []byte("hello"))
	}
	if len(decodedRecords) != 2 {
		t.Fatalf("len(decodedRecords) = %d, want 2", len(decodedRecords))
	}
	if decodedRecords[1].Type != protocol.Alert {
		t.Fatalf("decodedRecords[1].Type = %v, want %v", decodedRecords[1].Type, protocol.Alert)
	}

	if writeErr := <-writeErrCh; writeErr != nil {
		t.Fatalf("writer failed: %v", writeErr)
	}
}

func TestReadServerApplicationData_OnlyCloseNotify(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, chacha20poly1305.KeySize)
	iv := bytes.Repeat([]byte{0x44}, chacha20poly1305.NonceSize)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	writeErrCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()

		alertPayload := []byte{byte(protocol.AlertLevelWarning), byte(protocol.AlertCloseNotify)}
		alertRec, err := EncryptTLS13Record(key, iv, 0, protocol.Alert, alertPayload)
		if err != nil {
			writeErrCh <- err
			return
		}
		if _, err := serverConn.Write(alertRec.Marshal()); err != nil {
			writeErrCh <- err
			return
		}

		writeErrCh <- nil
	}()

	got, decodedRecords, err := ReadServerApplicationData(clientConn, key, iv)
	if err != nil {
		t.Fatalf("ReadServerApplicationData() failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
	if len(decodedRecords) != 1 {
		t.Fatalf("len(decodedRecords) = %d, want 1", len(decodedRecords))
	}
	if decodedRecords[0].Type != protocol.Alert {
		t.Fatalf("decodedRecords[0].Type = %v, want %v", decodedRecords[0].Type, protocol.Alert)
	}

	if writeErr := <-writeErrCh; writeErr != nil {
		t.Fatalf("writer failed: %v", writeErr)
	}
}
