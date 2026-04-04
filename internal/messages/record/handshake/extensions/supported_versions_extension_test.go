package extensions

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestSupportedVersions_Type(t *testing.T) {
	sv := &SupportedVersions{}
	if sv.Type() != protocol.ExtSupportedVersions {
		t.Errorf("SupportedVersions.Type() = %v, want %v", sv.Type(), protocol.ExtSupportedVersions)
	}
}

func TestSupportedVersions_MarshalPayload(t *testing.T) {
	tests := []struct {
		name     string
		versions []protocol.TLSVersion
		want     []byte
	}{
		{
			name:     "正常系：TLS 1.3のみ",
			versions: []protocol.TLSVersion{protocol.TLS_VERSION_1_3},
			want:     []byte{0x02, 0x03, 0x04},
		},
		{
			name:     "正常系：複数バージョン",
			versions: []protocol.TLSVersion{protocol.TLS_VERSION_1_3, protocol.TLS_VERSION_1_2},
			want:     []byte{0x04, 0x03, 0x04, 0x03, 0x03},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv := &SupportedVersions{Versions: tt.versions}
			got := sv.MarshalPayload()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("SupportedVersions.MarshalPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSupportedVersions_Unmarshal(t *testing.T) {
	tests := []struct {
		name         string
		payload      []byte
		wantSuccess  bool
		wantVersions []protocol.TLSVersion
	}{
		{
			name:         "正常系：TLS 1.3のみ",
			payload:      []byte{0x02, 0x03, 0x04},
			wantSuccess:  true,
			wantVersions: []protocol.TLSVersion{protocol.TLS_VERSION_1_3},
		},
		{
			name:         "正常系：複数バージョン",
			payload:      []byte{0x04, 0x03, 0x04, 0x03, 0x03},
			wantSuccess:  true,
			wantVersions: []protocol.TLSVersion{protocol.TLS_VERSION_1_3, protocol.TLS_VERSION_1_2},
		},
		{
			name:        "異常系：空のリスト",
			payload:     []byte{0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：奇数長",
			payload:     []byte{0x03, 0x03, 0x04, 0x03},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv := &SupportedVersions{}
			err := sv.Unmarshal(tt.payload)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("SupportedVersions.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if len(sv.Versions) != len(tt.wantVersions) {
				t.Errorf("len(Versions) = %d, want %d", len(sv.Versions), len(tt.wantVersions))
				return
			}
			for i, v := range sv.Versions {
				if v != tt.wantVersions[i] {
					t.Errorf("Versions[%d] = %v, want %v", i, v, tt.wantVersions[i])
				}
			}
		})
	}
}

func TestNewSupportedVersionsExtension(t *testing.T) {
	ext := NewSupportedVersionsExtension()
	if ext.Type != protocol.ExtSupportedVersions {
		t.Errorf("Type = %v, want %v", ext.Type, protocol.ExtSupportedVersions)
	}
}

func TestParseSupportedVersionsClient(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantCount   int
	}{
		{
			name:        "正常系：1バージョン",
			payload:     []byte{0x02, 0x03, 0x04},
			wantSuccess: true,
			wantCount:   1,
		},
		{
			name:        "正常系：2バージョン",
			payload:     []byte{0x04, 0x03, 0x04, 0x03, 0x03},
			wantSuccess: true,
			wantCount:   2,
		},
		{
			name:        "異常系：データ不足",
			payload:     []byte{0x02, 0x03},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versions, ok := ParseSupportedVersionsClient(tt.payload)
			if ok != tt.wantSuccess {
				t.Errorf("ParseSupportedVersionsClient() ok = %v, want %v", ok, tt.wantSuccess)
				return
			}
			if tt.wantSuccess && len(versions) != tt.wantCount {
				t.Errorf("len(versions) = %d, want %d", len(versions), tt.wantCount)
			}
		})
	}
}

func TestParseSupportedVersionsServer(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantVersion protocol.TLSVersion
	}{
		{
			name:        "正常系：TLS 1.3",
			payload:     []byte{0x03, 0x04},
			wantSuccess: true,
			wantVersion: protocol.TLS_VERSION_1_3,
		},
		{
			name:        "正常系：TLS 1.2",
			payload:     []byte{0x03, 0x03},
			wantSuccess: true,
			wantVersion: protocol.TLS_VERSION_1_2,
		},
		{
			name:        "異常系：長すぎる",
			payload:     []byte{0x03, 0x04, 0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：短すぎる",
			payload:     []byte{0x03},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, ok := ParseSupportedVersionsServer(tt.payload)
			if ok != tt.wantSuccess {
				t.Errorf("ParseSupportedVersionsServer() ok = %v, want %v", ok, tt.wantSuccess)
				return
			}
			if tt.wantSuccess && version != tt.wantVersion {
				t.Errorf("version = %v, want %v", version, tt.wantVersion)
			}
		})
	}
}

func TestSupportedVersions_RoundTrip(t *testing.T) {
	original := &SupportedVersions{
		Versions: []protocol.TLSVersion{protocol.TLS_VERSION_1_3, protocol.TLS_VERSION_1_2},
	}

	payload := original.MarshalPayload()

	parsed := &SupportedVersions{}
	if err := parsed.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.Versions) != len(original.Versions) {
		t.Fatalf("len mismatch: got %d, want %d", len(parsed.Versions), len(original.Versions))
	}
	for i := range original.Versions {
		if parsed.Versions[i] != original.Versions[i] {
			t.Errorf("Versions[%d] = %v, want %v", i, parsed.Versions[i], original.Versions[i])
		}
	}
}
