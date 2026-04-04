package extensions

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestSupportedGroups_Type(t *testing.T) {
	sg := &SupportedGroups{}
	if sg.Type() != protocol.ExtSupportedCurves {
		t.Errorf("SupportedGroups.Type() = %v, want %v", sg.Type(), protocol.ExtSupportedCurves)
	}
}

func TestSupportedGroups_MarshalPayload(t *testing.T) {
	tests := []struct {
		name   string
		groups []protocol.CurveID
		want   []byte
	}{
		{
			name:   "正常系：X25519のみ",
			groups: []protocol.CurveID{protocol.X25519},
			want:   []byte{0x00, 0x02, 0x00, 0x1d},
		},
		{
			name:   "正常系：複数グループ",
			groups: []protocol.CurveID{protocol.X25519, protocol.CurveP256},
			want:   []byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := &SupportedGroups{Groups: tt.groups}
			got := sg.MarshalPayload()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("SupportedGroups.MarshalPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSupportedGroups_Unmarshal(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantGroups  []protocol.CurveID
	}{
		{
			name:        "正常系：X25519のみ",
			payload:     []byte{0x00, 0x02, 0x00, 0x1d},
			wantSuccess: true,
			wantGroups:  []protocol.CurveID{protocol.X25519},
		},
		{
			name:        "正常系：複数グループ",
			payload:     []byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17},
			wantSuccess: true,
			wantGroups:  []protocol.CurveID{protocol.X25519, protocol.CurveP256},
		},
		{
			name:        "異常系：空のリスト",
			payload:     []byte{0x00, 0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：奇数長",
			payload:     []byte{0x00, 0x03, 0x00, 0x1d, 0x00},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := &SupportedGroups{}
			err := sg.Unmarshal(tt.payload)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("SupportedGroups.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if len(sg.Groups) != len(tt.wantGroups) {
				t.Errorf("len(Groups) = %d, want %d", len(sg.Groups), len(tt.wantGroups))
				return
			}
			for i, g := range sg.Groups {
				if g != tt.wantGroups[i] {
					t.Errorf("Groups[%d] = %v, want %v", i, g, tt.wantGroups[i])
				}
			}
		})
	}
}

func TestNewSupportedGroupsExtension(t *testing.T) {
	ext := NewSupportedGroupsExtension()
	if ext.Type != protocol.ExtSupportedCurves {
		t.Errorf("Type = %v, want %v", ext.Type, protocol.ExtSupportedCurves)
	}
}

func TestParseSupportedCurves(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantCount   int
	}{
		{
			name:        "正常系：1グループ",
			payload:     []byte{0x00, 0x02, 0x00, 0x1d},
			wantSuccess: true,
			wantCount:   1,
		},
		{
			name:        "正常系：3グループ",
			payload:     []byte{0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18},
			wantSuccess: true,
			wantCount:   3,
		},
		{
			name:        "異常系：空",
			payload:     []byte{0x00, 0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：データ不足",
			payload:     []byte{0x00, 0x04, 0x00, 0x1d},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curves, ok := ParseSupportedCurves(tt.payload)
			if ok != tt.wantSuccess {
				t.Errorf("ParseSupportedCurves() ok = %v, want %v", ok, tt.wantSuccess)
				return
			}
			if tt.wantSuccess && len(curves) != tt.wantCount {
				t.Errorf("len(curves) = %d, want %d", len(curves), tt.wantCount)
			}
		})
	}
}

func TestSupportedGroups_RoundTrip(t *testing.T) {
	original := &SupportedGroups{
		Groups: []protocol.CurveID{protocol.X25519, protocol.CurveP256, protocol.CurveP384},
	}

	payload := original.MarshalPayload()

	parsed := &SupportedGroups{}
	if err := parsed.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.Groups) != len(original.Groups) {
		t.Fatalf("len mismatch: got %d, want %d", len(parsed.Groups), len(original.Groups))
	}
	for i := range original.Groups {
		if parsed.Groups[i] != original.Groups[i] {
			t.Errorf("Groups[%d] = %v, want %v", i, parsed.Groups[i], original.Groups[i])
		}
	}
}
