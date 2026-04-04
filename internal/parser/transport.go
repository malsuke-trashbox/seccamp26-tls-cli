package parser

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
)

const (
	DefaultDialTimeout    = 5 * time.Second
	DefaultReadBufferSize = 4096
)

var (
	ErrNilConn   = errors.New("tls: net.Conn is nil")
	ErrNilRecord = errors.New("tls: tls record is nil")
)

// DialTCP establishes a TCP connection to serverName with default TLS port.
func DialTCP(serverName string, timeout time.Duration) (net.Conn, error) {
	return DialTCPWithPort(serverName, DefaultTLSPort, timeout)
}

// DialTCPWithPort establishes a TCP connection to serverName:port.
func DialTCPWithPort(serverName string, port int, timeout time.Duration) (net.Conn, error) {
	address, err := BuildServerAddress(serverName, port)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to connect %s: %w", address, err)
	}
	return conn, nil
}

// SendRecord serializes and sends a TLS record over the connection.
func SendRecord(conn net.Conn, rec *record.TLSPlaintext) error {
	if conn == nil {
		return ErrNilConn
	}
	if rec == nil {
		return ErrNilRecord
	}

	if _, err := conn.Write(rec.Marshal()); err != nil {
		return fmt.Errorf("tls: failed to write record: %w", err)
	}
	return nil
}

// ReadFromConn reads one chunk from a connection.
func ReadFromConn(conn net.Conn, bufferSize int) ([]byte, error) {
	if conn == nil {
		return nil, ErrNilConn
	}
	if bufferSize <= 0 {
		return nil, fmt.Errorf("tls: invalid buffer size: %d", bufferSize)
	}

	buffer := make([]byte, bufferSize)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to read from connection: %w", err)
	}

	data := make([]byte, n)
	copy(data, buffer[:n])
	return data, nil
}

// ReadTLSRecords reads once from connection and parses all records in the chunk.
func ReadTLSRecords(conn net.Conn, bufferSize int) ([]record.TLSPlaintext, error) {
	data, err := ReadFromConn(conn, bufferSize)
	if err != nil {
		return nil, err
	}
	return ParseTLSRecords(data)
}

// ExchangeClientHello sends ClientHello record then reads and parses response records.
func ExchangeClientHello(conn net.Conn, clientHelloRecord *record.TLSPlaintext, bufferSize int) ([]record.TLSPlaintext, error) {
	if err := SendRecord(conn, clientHelloRecord); err != nil {
		return nil, err
	}
	return ReadTLSRecords(conn, bufferSize)
}
