package handshake

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestCertificate_Unmarshal(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantSuccess bool
		wantCerts   int
	}{
		{
			name: "正常系：証明書1つ",
			data: func() []byte {
				// Certificate request context length: 0
				data := []byte{0x00}
				// Certificate list length (3 bytes)
				cert := []byte("test certificate data")
				certLen := len(cert)
				listLen := 3 + certLen + 2 // cert_len(3) + cert + extensions_len(2)
				data = append(data, byte(listLen>>16), byte(listLen>>8), byte(listLen))
				// Certificate length (3 bytes)
				data = append(data, byte(certLen>>16), byte(certLen>>8), byte(certLen))
				// Certificate data
				data = append(data, cert...)
				// Extensions length: 0
				data = append(data, 0x00, 0x00)
				return data
			}(),
			wantSuccess: true,
			wantCerts:   1,
		},
		{
			name: "正常系：証明書2つ",
			data: func() []byte {
				data := []byte{0x00}
				cert1 := []byte("first certificate")
				cert2 := []byte("second certificate")
				listLen := (3 + len(cert1) + 2) + (3 + len(cert2) + 2)
				data = append(data, byte(listLen>>16), byte(listLen>>8), byte(listLen))
				// First certificate
				data = append(data, byte(len(cert1)>>16), byte(len(cert1)>>8), byte(len(cert1)))
				data = append(data, cert1...)
				data = append(data, 0x00, 0x00)
				// Second certificate
				data = append(data, byte(len(cert2)>>16), byte(len(cert2)>>8), byte(len(cert2)))
				data = append(data, cert2...)
				data = append(data, 0x00, 0x00)
				return data
			}(),
			wantSuccess: true,
			wantCerts:   2,
		},
		{
			name: "正常系：空の証明書リスト",
			data: func() []byte {
				data := []byte{0x00}       // context length
				data = append(data, 0x00, 0x00, 0x00) // list length: 0
				return data
			}(),
			wantSuccess: true,
			wantCerts:   0,
		},
		{
			name: "正常系：ハンドシェイクヘッダー付き",
			data: func() []byte {
				// Certificate message without header
				inner := []byte{0x00} // context
				inner = append(inner, 0x00, 0x00, 0x00) // empty cert list

				// Add handshake header
				data := []byte{byte(protocol.TypeCertificate)}
				data = append(data, byte(len(inner)>>16), byte(len(inner)>>8), byte(len(inner)))
				data = append(data, inner...)
				return data
			}(),
			wantSuccess: true,
			wantCerts:   0,
		},
		{
			name: "異常系：非空のコンテキスト",
			data: func() []byte {
				data := []byte{0x05} // context length: 5 (should be 0 for server cert)
				data = append(data, []byte("ctx01")...)
				data = append(data, 0x00, 0x00, 0x00) // empty list
				return data
			}(),
			wantSuccess: false,
		},
		{
			name:        "異常系：データが短すぎる",
			data:        []byte{0x00, 0x00},
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
			cert := &Certificate{}
			err := cert.Unmarshal(tt.data)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("Certificate.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if len(cert.Certificates) != tt.wantCerts {
				t.Errorf("len(Certificate.Certificates) = %d, want %d", len(cert.Certificates), tt.wantCerts)
			}
		})
	}
}

func TestCertificate_Unmarshal_CertificateContent(t *testing.T) {
	cert1Data := []byte("first certificate content here")
	cert2Data := []byte("second cert")

	data := func() []byte {
		d := []byte{0x00} // context
		listLen := (3 + len(cert1Data) + 2) + (3 + len(cert2Data) + 2)
		d = append(d, byte(listLen>>16), byte(listLen>>8), byte(listLen))
		// First cert
		d = append(d, byte(len(cert1Data)>>16), byte(len(cert1Data)>>8), byte(len(cert1Data)))
		d = append(d, cert1Data...)
		d = append(d, 0x00, 0x00)
		// Second cert
		d = append(d, byte(len(cert2Data)>>16), byte(len(cert2Data)>>8), byte(len(cert2Data)))
		d = append(d, cert2Data...)
		d = append(d, 0x00, 0x00)
		return d
	}()

	cert := &Certificate{}
	if err := cert.Unmarshal(data); err != nil {
		t.Fatalf("Certificate.Unmarshal() failed: %v", err)
	}

	if len(cert.Certificates) != 2 {
		t.Fatalf("len(Certificates) = %d, want 2", len(cert.Certificates))
	}

	if !bytes.Equal(cert.Certificates[0], cert1Data) {
		t.Errorf("Certificates[0] = %v, want %v", cert.Certificates[0], cert1Data)
	}
	if !bytes.Equal(cert.Certificates[1], cert2Data) {
		t.Errorf("Certificates[1] = %v, want %v", cert.Certificates[1], cert2Data)
	}
}

func TestCertificate_Unmarshal_ClearsExisting(t *testing.T) {
	// First unmarshal with certificates
	data1 := func() []byte {
		d := []byte{0x00}
		cert := []byte("test")
		listLen := 3 + len(cert) + 2
		d = append(d, byte(listLen>>16), byte(listLen>>8), byte(listLen))
		d = append(d, byte(len(cert)>>16), byte(len(cert)>>8), byte(len(cert)))
		d = append(d, cert...)
		d = append(d, 0x00, 0x00)
		return d
	}()

	cert := &Certificate{}
	if err := cert.Unmarshal(data1); err != nil {
		t.Fatalf("First Unmarshal failed: %v", err)
	}
	if len(cert.Certificates) != 1 {
		t.Fatalf("After first unmarshal: len = %d, want 1", len(cert.Certificates))
	}

	// Second unmarshal with empty list should clear existing
	data2 := []byte{0x00, 0x00, 0x00, 0x00}
	if err := cert.Unmarshal(data2); err != nil {
		t.Fatalf("Second Unmarshal failed: %v", err)
	}
	if len(cert.Certificates) != 0 {
		t.Errorf("After second unmarshal: len = %d, want 0", len(cert.Certificates))
	}
}
