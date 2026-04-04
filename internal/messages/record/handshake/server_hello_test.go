package handshake

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestServerHello_Unmarshal(t *testing.T) {
	tests := []struct {
		name              string
		data              []byte
		wantSuccess       bool
		wantVersion       protocol.TLSVersion
		wantCipherSuite   protocol.CipherSuite
		wantSessionIDLen  int
		wantCompression   byte
	}{
		{
			name: "正常系：基本的なServerHello（拡張なし）",
			data: func() []byte {
				// Version (legacy): TLS 1.2
				data := []byte{0x03, 0x03}
				// Random: 32 bytes
				data = append(data, make([]byte, 32)...)
				// Session ID length: 0
				data = append(data, 0x00)
				// Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
				data = append(data, 0x13, 0x01)
				// Compression method: null (0)
				data = append(data, 0x00)
				return data
			}(),
			wantSuccess:      true,
			wantVersion:      protocol.TLS_VERSION_1_2,
			wantCipherSuite:  protocol.TLS_AES_128_GCM_SHA256,
			wantSessionIDLen: 0,
			wantCompression:  0,
		},
		{
			name: "正常系：セッションIDあり",
			data: func() []byte {
				// Version
				data := []byte{0x03, 0x03}
				// Random
				data = append(data, make([]byte, 32)...)
				// Session ID length: 32
				data = append(data, 0x20)
				// Session ID: 32 bytes
				data = append(data, make([]byte, 32)...)
				// Cipher Suite
				data = append(data, 0x13, 0x03) // ChaCha20-Poly1305
				// Compression
				data = append(data, 0x00)
				return data
			}(),
			wantSuccess:      true,
			wantVersion:      protocol.TLS_VERSION_1_2,
			wantCipherSuite:  protocol.TLS_CHACHA20_POLY1305_SHA256,
			wantSessionIDLen: 32,
			wantCompression:  0,
		},
		{
			name: "正常系：拡張あり（supported_versions）",
			data: func() []byte {
				// Version
				data := []byte{0x03, 0x03}
				// Random
				data = append(data, make([]byte, 32)...)
				// Session ID length
				data = append(data, 0x00)
				// Cipher Suite
				data = append(data, 0x13, 0x01)
				// Compression
				data = append(data, 0x00)
				// Extensions length: 6
				data = append(data, 0x00, 0x06)
				// supported_versions extension (type=43)
				data = append(data, 0x00, 0x2b) // type
				data = append(data, 0x00, 0x02) // length
				data = append(data, 0x03, 0x04) // TLS 1.3
				return data
			}(),
			wantSuccess:      true,
			wantVersion:      protocol.TLS_VERSION_1_2,
			wantCipherSuite:  protocol.TLS_AES_128_GCM_SHA256,
			wantSessionIDLen: 0,
			wantCompression:  0,
		},
		{
			name: "正常系：ハンドシェイクヘッダー付き",
			data: func() []byte {
				// Handshake header
				data := []byte{byte(protocol.TypeServerHello)}
				// Message length (3 bytes): 38 = 2 + 32 + 1 + 2 + 1
				data = append(data, 0x00, 0x00, 0x26)
				// Version
				data = append(data, 0x03, 0x03)
				// Random
				data = append(data, make([]byte, 32)...)
				// Session ID length
				data = append(data, 0x00)
				// Cipher Suite
				data = append(data, 0x13, 0x01)
				// Compression
				data = append(data, 0x00)
				return data
			}(),
			wantSuccess:      true,
			wantVersion:      protocol.TLS_VERSION_1_2,
			wantCipherSuite:  protocol.TLS_AES_128_GCM_SHA256,
			wantSessionIDLen: 0,
			wantCompression:  0,
		},
		{
			name:        "異常系：データが短すぎる",
			data:        []byte{0x03, 0x03},
			wantSuccess: false,
		},
		{
			name:        "異常系：空のデータ",
			data:        []byte{},
			wantSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sh := &ServerHello{}
			err := sh.Unmarshal(tt.data)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("ServerHello.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if sh.ProtocolVersion != tt.wantVersion {
				t.Errorf("ServerHello.ProtocolVersion = %v, want %v", sh.ProtocolVersion, tt.wantVersion)
			}
			if sh.CipherSuite != tt.wantCipherSuite {
				t.Errorf("ServerHello.CipherSuite = %v, want %v", sh.CipherSuite, tt.wantCipherSuite)
			}
			if len(sh.SessionID) != tt.wantSessionIDLen {
				t.Errorf("len(ServerHello.SessionID) = %d, want %d", len(sh.SessionID), tt.wantSessionIDLen)
			}
			if sh.CompressionMethod != tt.wantCompression {
				t.Errorf("ServerHello.CompressionMethod = %v, want %v", sh.CompressionMethod, tt.wantCompression)
			}
		})
	}
}

func TestServerHello_Unmarshal_WithKeyShare(t *testing.T) {
	// ServerHello with key_share extension
	data := func() []byte {
		// Version
		d := []byte{0x03, 0x03}
		// Random
		d = append(d, make([]byte, 32)...)
		// Session ID length
		d = append(d, 0x00)
		// Cipher Suite
		d = append(d, 0x13, 0x01)
		// Compression
		d = append(d, 0x00)
		// Extensions length
		keyShareData := make([]byte, 32) // 32-byte public key
		extLen := 2 + 2 + 2 + 2 + len(keyShareData) // type + len + group + key_len + key
		d = append(d, byte(extLen>>8), byte(extLen))
		// key_share extension (type=51)
		d = append(d, 0x00, 0x33)                                  // type
		d = append(d, 0x00, byte(2+2+len(keyShareData)))           // length
		d = append(d, 0x00, 0x1d)                                  // X25519 group
		d = append(d, 0x00, byte(len(keyShareData)))               // key length
		d = append(d, keyShareData...)                              // public key
		return d
	}()

	sh := &ServerHello{}
	if err := sh.Unmarshal(data); err != nil {
		t.Fatalf("ServerHello.Unmarshal() failed: %v", err)
	}
	serverShare, err := sh.ServerShare()
	if err != nil {
		t.Fatalf("ServerHello.ServerShare() failed: %v", err)
	}

	if serverShare.Group != protocol.X25519 {
		t.Errorf("ServerShare.Group = %v, want %v", serverShare.Group, protocol.X25519)
	}
	if len(serverShare.Data) != 32 {
		t.Errorf("len(ServerShare.Data) = %d, want 32", len(serverShare.Data))
	}
}

func TestServerHello_Unmarshal_DuplicateExtension(t *testing.T) {
	// ServerHello with duplicate extensions should fail
	data := func() []byte {
		// Version
		d := []byte{0x03, 0x03}
		// Random
		d = append(d, make([]byte, 32)...)
		// Session ID length
		d = append(d, 0x00)
		// Cipher Suite
		d = append(d, 0x13, 0x01)
		// Compression
		d = append(d, 0x00)
		// Extensions length: 12 (two supported_versions extensions)
		d = append(d, 0x00, 0x0c)
		// First supported_versions
		d = append(d, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
		// Duplicate supported_versions
		d = append(d, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
		return d
	}()

	sh := &ServerHello{}
	if err := sh.Unmarshal(data); err == nil {
		t.Error("ServerHello.Unmarshal() should fail with duplicate extensions")
	}
}

func TestServerHello_Original(t *testing.T) {
	originalData := func() []byte {
		d := []byte{0x03, 0x03}
		d = append(d, make([]byte, 32)...)
		d = append(d, 0x00)
		d = append(d, 0x13, 0x01)
		d = append(d, 0x00)
		return d
	}()

	sh := &ServerHello{}
	if err := sh.Unmarshal(originalData); err != nil {
		t.Fatalf("ServerHello.Unmarshal() failed: %v", err)
	}

	if !bytes.Equal(sh.Original, originalData) {
		t.Error("ServerHello.Original should preserve the original data")
	}
}

func TestServerHello_Random(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}

	data := func() []byte {
		d := []byte{0x03, 0x03}
		d = append(d, random...)
		d = append(d, 0x00)
		d = append(d, 0x13, 0x01)
		d = append(d, 0x00)
		return d
	}()

	sh := &ServerHello{}
	if err := sh.Unmarshal(data); err != nil {
		t.Fatalf("ServerHello.Unmarshal() failed: %v", err)
	}

	if !bytes.Equal(sh.Random[:], random) {
		t.Errorf("ServerHello.Random = %v, want %v", sh.Random[:], random)
	}
}
