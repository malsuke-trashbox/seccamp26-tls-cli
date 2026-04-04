package parser

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

const (
	DefaultTLSPort = 443
	minPort        = 1
	maxPort        = 65535
)

const defaultLegacyCompressionMethod = 0x00

var (
	ErrEmptyServerName = errors.New("tls: server name is empty")
)

var defaultClientCipherSuites = []protocol.CipherSuite{
	protocol.TLS_CHACHA20_POLY1305_SHA256,
	protocol.TLS_AES_128_GCM_SHA256,
	protocol.TLS_AES_256_GCM_SHA384,
}

// NormalizeServerName trims spaces and trailing dots from a host name.
func NormalizeServerName(serverName string) (string, error) {
	normalized := strings.TrimSpace(serverName)
	normalized = strings.TrimSuffix(normalized, ".")
	if normalized == "" {
		return "", ErrEmptyServerName
	}
	if strings.Contains(normalized, ":") {
		return "", errors.New("tls: server name must not include a port")
	}
	if strings.ContainsAny(normalized, " \t\n\r") {
		return "", errors.New("tls: server name must not contain whitespace")
	}
	return normalized, nil
}

// BuildServerAddress returns a host:port address for TCP connection.
func BuildServerAddress(serverName string, port int) (string, error) {
	normalized, err := NormalizeServerName(serverName)
	if err != nil {
		return "", err
	}
	if port < minPort || port > maxPort {
		return "", fmt.Errorf("tls: invalid port: %d", port)
	}
	return net.JoinHostPort(normalized, fmt.Sprintf("%d", port)), nil
}

// DefaultCipherSuites returns a copy of recommended TLS 1.3 cipher suites.
func DefaultCipherSuites() []protocol.CipherSuite {
	suites := make([]protocol.CipherSuite, len(defaultClientCipherSuites))
	copy(suites, defaultClientCipherSuites)
	return suites
}

// DefaultCompressionMethods returns the legacy compression method list for TLS 1.3 ClientHello.
func DefaultCompressionMethods() []byte {
	return []byte{defaultLegacyCompressionMethod}
}

// DefaultClientHelloExtensions returns baseline extensions used by this learning project.
func DefaultClientHelloExtensions(serverName string, keySharePublicKey []byte) ([]extensions.Extension, error) {
	normalized, err := NormalizeServerName(serverName)
	if err != nil {
		return nil, err
	}
	if len(keySharePublicKey) != key.X25519PublicKeyBytes {
		return nil, fmt.Errorf("tls: invalid key_share public key length: %d", len(keySharePublicKey))
	}

	publicKey := make([]byte, len(keySharePublicKey))
	copy(publicKey, keySharePublicKey)

	exts := []extensions.Extension{
		extensions.NewServerNameExtension(normalized),
		extensions.NewSupportedVersionsExtension(),
		extensions.NewSupportedGroupsExtension(),
		extensions.NewSignatureAlgorithmsExtension(),
		extensions.NewKeyShareExtension(publicKey),
	}
	return exts, nil
}

// NewClientHelloWithCipherSuites builds a ClientHello message with custom cipher suites.
func NewClientHelloWithCipherSuites(random [key.RandomBytes32Length]byte, serverName string, keySharePublicKey []byte, cipherSuites []protocol.CipherSuite) (*handshake.ClientHello, error) {
	exts, err := DefaultClientHelloExtensions(serverName, keySharePublicKey)
	if err != nil {
		return nil, err
	}

	suites := cipherSuites
	if len(suites) == 0 {
		suites = DefaultCipherSuites()
	} else {
		suites = append([]protocol.CipherSuite(nil), suites...)
	}

	clientHello := handshake.NewClientHello(random, exts)
	clientHello.CipherSuites = suites
	clientHello.LegacyCompressionMethods = DefaultCompressionMethods()
	clientHello.ProtocolVersion = protocol.TLS_VERSION_1_2

	return clientHello, nil
}

// NewDefaultClientHello builds a ClientHello message with default cipher suites.
func NewDefaultClientHello(random [key.RandomBytes32Length]byte, serverName string, keySharePublicKey []byte) (*handshake.ClientHello, error) {
	return NewClientHelloWithCipherSuites(random, serverName, keySharePublicKey, nil)
}

// NewClientHelloRecordFromMessage wraps a ClientHello into Handshake and TLSPlaintext records.
func NewClientHelloRecordFromMessage(clientHello *handshake.ClientHello) (*record.TLSPlaintext, error) {
	if clientHello == nil {
		return nil, errors.New("tls: client hello is nil")
	}

	hs, err := handshake.NewHandshake(clientHello)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to build handshake message: %w", err)
	}

	rec, err := record.NewTLSPlaintext(protocol.Handshake, hs.Marshal())
	if err != nil {
		return nil, fmt.Errorf("tls: failed to build record: %w", err)
	}
	return rec, nil
}

// NewDefaultClientHelloRecord builds a default ClientHello record for handshake start.
func NewDefaultClientHelloRecord(random [key.RandomBytes32Length]byte, serverName string, keySharePublicKey []byte) (*record.TLSPlaintext, error) {
	clientHello, err := NewDefaultClientHello(random, serverName, keySharePublicKey)
	if err != nil {
		return nil, err
	}
	return NewClientHelloRecordFromMessage(clientHello)
}
