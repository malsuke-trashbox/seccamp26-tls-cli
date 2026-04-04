package handshake

import (
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestEncryptedExtensions_Unmarshal(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		wantSuccess   bool
		wantServerAck bool
		wantExtsCount int
	}{
		{
			name: "正常系：空の拡張",
			data: func() []byte {
				// Extensions length: 0
				return []byte{0x00, 0x00}
			}(),
			wantSuccess:   true,
			wantServerAck: false,
			wantExtsCount: 0,
		},
		{
			name: "正常系：server_name ACK",
			data: func() []byte {
				// Extensions length: 4
				d := []byte{0x00, 0x04}
				// server_name extension (type=0) with empty payload
				d = append(d, 0x00, 0x00) // type
				d = append(d, 0x00, 0x00) // length: 0
				return d
			}(),
			wantSuccess:   true,
			wantServerAck: true,
			wantExtsCount: 0,
		},
		{
			name: "正常系：ハンドシェイクヘッダー付き",
			data: func() []byte {
				// Inner: empty extensions
				inner := []byte{0x00, 0x00}

				// Handshake header
				d := []byte{byte(protocol.TypeEncryptedExtensions)}
				d = append(d, byte(len(inner)>>16), byte(len(inner)>>8), byte(len(inner)))
				d = append(d, inner...)
				return d
			}(),
			wantSuccess:   true,
			wantServerAck: false,
			wantExtsCount: 0,
		},
		{
			name: "異常系：server_name拡張が非空ペイロード",
			data: func() []byte {
				// Extensions length: 5
				d := []byte{0x00, 0x05}
				// server_name extension with non-empty payload
				d = append(d, 0x00, 0x00) // type
				d = append(d, 0x00, 0x01) // length: 1
				d = append(d, 0x00)       // invalid non-empty payload
				return d
			}(),
			wantSuccess: false,
		},
		{
			name: "異常系：重複拡張",
			data: func() []byte {
				// Extensions length: 8 (two server_name extensions)
				d := []byte{0x00, 0x08}
				// First server_name
				d = append(d, 0x00, 0x00, 0x00, 0x00)
				// Duplicate server_name
				d = append(d, 0x00, 0x00, 0x00, 0x00)
				return d
			}(),
			wantSuccess: false,
		},
		{
			name:        "異常系：データが短すぎる",
			data:        []byte{0x00},
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
			ee := &EncryptedExtensions{}
			err := ee.Unmarshal(tt.data)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("EncryptedExtensions.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if ee.ServerNameAck != tt.wantServerAck {
				t.Errorf("EncryptedExtensions.ServerNameAck = %v, want %v", ee.ServerNameAck, tt.wantServerAck)
			}
			if len(ee.Extensions) != tt.wantExtsCount {
				t.Errorf("len(EncryptedExtensions.Extensions) = %d, want %d", len(ee.Extensions), tt.wantExtsCount)
			}
		})
	}
}

func TestEncryptedExtensions_Unmarshal_OtherExtensions(t *testing.T) {
	// EncryptedExtensions with a non-server_name extension
	data := func() []byte {
		// Extensions length: 8
		d := []byte{0x00, 0x08}
		// Some other extension (type=100)
		d = append(d, 0x00, 0x64) // type: 100
		d = append(d, 0x00, 0x04) // length: 4
		d = append(d, 0x01, 0x02, 0x03, 0x04)
		return d
	}()

	ee := &EncryptedExtensions{}
	if err := ee.Unmarshal(data); err != nil {
		t.Fatalf("EncryptedExtensions.Unmarshal() failed: %v", err)
	}

	if ee.ServerNameAck {
		t.Error("ServerNameAck should be false")
	}
	if len(ee.Extensions) != 1 {
		t.Fatalf("len(Extensions) = %d, want 1", len(ee.Extensions))
	}
	if ee.Extensions[0].Type != protocol.ExtensionType(100) {
		t.Errorf("Extensions[0].Type = %v, want 100", ee.Extensions[0].Type)
	}
}

func TestEncryptedExtensions_Unmarshal_MultipleExtensions(t *testing.T) {
	// server_name ACK + another extension
	data := func() []byte {
		// Extensions length
		d := []byte{0x00, 0x0c}
		// server_name ACK
		d = append(d, 0x00, 0x00, 0x00, 0x00)
		// Another extension (type=200)
		d = append(d, 0x00, 0xc8) // type: 200
		d = append(d, 0x00, 0x04) // length: 4
		d = append(d, 0xaa, 0xbb, 0xcc, 0xdd)
		return d
	}()

	ee := &EncryptedExtensions{}
	if err := ee.Unmarshal(data); err != nil {
		t.Fatalf("EncryptedExtensions.Unmarshal() failed: %v", err)
	}

	if !ee.ServerNameAck {
		t.Error("ServerNameAck should be true")
	}
	if len(ee.Extensions) != 1 {
		t.Fatalf("len(Extensions) = %d, want 1", len(ee.Extensions))
	}
}

func TestEncryptedExtensions_Unmarshal_ClearsExisting(t *testing.T) {
	// First unmarshal with server_name ACK
	data1 := []byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
	ee := &EncryptedExtensions{}
	if err := ee.Unmarshal(data1); err != nil {
		t.Fatalf("First Unmarshal failed: %v", err)
	}
	if !ee.ServerNameAck {
		t.Fatal("First unmarshal: ServerNameAck should be true")
	}

	// Second unmarshal with empty extensions
	data2 := []byte{0x00, 0x00}
	if err := ee.Unmarshal(data2); err != nil {
		t.Fatalf("Second Unmarshal failed: %v", err)
	}
	if ee.ServerNameAck {
		t.Error("Second unmarshal: ServerNameAck should be false")
	}
}
