package extensions

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestSignatureAlgorithms_Type(t *testing.T) {
	sa := &SignatureAlgorithms{}
	if sa.Type() != protocol.ExtSignatureAlgorithms {
		t.Errorf("SignatureAlgorithms.Type() = %v, want %v", sa.Type(), protocol.ExtSignatureAlgorithms)
	}
}

func TestSignatureAlgorithms_MarshalPayload(t *testing.T) {
	tests := []struct {
		name       string
		algorithms []protocol.SignatureScheme
		want       []byte
	}{
		{
			name:       "正常系：1アルゴリズム",
			algorithms: []protocol.SignatureScheme{protocol.ECDSAWithP256AndSHA256},
			want:       []byte{0x00, 0x02, 0x04, 0x03},
		},
		{
			name:       "正常系：複数アルゴリズム",
			algorithms: []protocol.SignatureScheme{protocol.ECDSAWithP256AndSHA256, protocol.PSSWithSHA256},
			want:       []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := &SignatureAlgorithms{Algorithms: tt.algorithms}
			got := sa.MarshalPayload()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("SignatureAlgorithms.MarshalPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureAlgorithms_Unmarshal(t *testing.T) {
	tests := []struct {
		name           string
		payload        []byte
		wantSuccess    bool
		wantAlgorithms []protocol.SignatureScheme
	}{
		{
			name:           "正常系：1アルゴリズム",
			payload:        []byte{0x00, 0x02, 0x04, 0x03},
			wantSuccess:    true,
			wantAlgorithms: []protocol.SignatureScheme{protocol.ECDSAWithP256AndSHA256},
		},
		{
			name:           "正常系：複数アルゴリズム",
			payload:        []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04},
			wantSuccess:    true,
			wantAlgorithms: []protocol.SignatureScheme{protocol.ECDSAWithP256AndSHA256, protocol.PSSWithSHA256},
		},
		{
			name:        "異常系：空のリスト",
			payload:     []byte{0x00, 0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：奇数長",
			payload:     []byte{0x00, 0x03, 0x04, 0x03, 0x08},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := &SignatureAlgorithms{}
			err := sa.Unmarshal(tt.payload)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("SignatureAlgorithms.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if len(sa.Algorithms) != len(tt.wantAlgorithms) {
				t.Errorf("len(Algorithms) = %d, want %d", len(sa.Algorithms), len(tt.wantAlgorithms))
				return
			}
			for i, alg := range sa.Algorithms {
				if alg != tt.wantAlgorithms[i] {
					t.Errorf("Algorithms[%d] = %v, want %v", i, alg, tt.wantAlgorithms[i])
				}
			}
		})
	}
}

func TestNewSignatureAlgorithmsExtension(t *testing.T) {
	ext := NewSignatureAlgorithmsExtension()
	if ext.Type != protocol.ExtSignatureAlgorithms {
		t.Errorf("Type = %v, want %v", ext.Type, protocol.ExtSignatureAlgorithms)
	}
}

func TestParseSignatureAlgorithms(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantCount   int
	}{
		{
			name:        "正常系：1アルゴリズム",
			payload:     []byte{0x00, 0x02, 0x04, 0x03},
			wantSuccess: true,
			wantCount:   1,
		},
		{
			name:        "正常系：4アルゴリズム",
			payload:     []byte{0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x07},
			wantSuccess: true,
			wantCount:   4,
		},
		{
			name:        "異常系：空",
			payload:     []byte{0x00, 0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：データ不足",
			payload:     []byte{0x00, 0x04, 0x04, 0x03},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algs, ok := ParseSignatureAlgorithms(tt.payload)
			if ok != tt.wantSuccess {
				t.Errorf("ParseSignatureAlgorithms() ok = %v, want %v", ok, tt.wantSuccess)
				return
			}
			if tt.wantSuccess && len(algs) != tt.wantCount {
				t.Errorf("len(algs) = %d, want %d", len(algs), tt.wantCount)
			}
		})
	}
}

func TestSignatureAlgorithms_RoundTrip(t *testing.T) {
	original := &SignatureAlgorithms{
		Algorithms: []protocol.SignatureScheme{
			protocol.ECDSAWithP256AndSHA256,
			protocol.PSSWithSHA256,
			protocol.PKCS1WithSHA256,
			protocol.Ed25519,
		},
	}

	payload := original.MarshalPayload()

	parsed := &SignatureAlgorithms{}
	if err := parsed.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.Algorithms) != len(original.Algorithms) {
		t.Fatalf("len mismatch: got %d, want %d", len(parsed.Algorithms), len(original.Algorithms))
	}
	for i := range original.Algorithms {
		if parsed.Algorithms[i] != original.Algorithms[i] {
			t.Errorf("Algorithms[%d] = %v, want %v", i, parsed.Algorithms[i], original.Algorithms[i])
		}
	}
}
