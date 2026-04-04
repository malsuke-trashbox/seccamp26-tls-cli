package extensions

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestPSKKeyExchangeModes_Type(t *testing.T) {
	p := &PSKKeyExchangeModes{}
	if p.Type() != protocol.ExtPSKKeyExchangeModes {
		t.Errorf("PSKKeyExchangeModes.Type() = %v, want %v", p.Type(), protocol.ExtPSKKeyExchangeModes)
	}
}

func TestPSKKeyExchangeModes_MarshalPayload(t *testing.T) {
	tests := []struct {
		name  string
		modes []PSKKeyExchangeMode
		want  []byte
	}{
		{
			name:  "正常系：psk_dhe_keのみ",
			modes: []PSKKeyExchangeMode{PSKModeDHE},
			want:  []byte{0x01, 0x01},
		},
		{
			name:  "正常系：psk_keのみ",
			modes: []PSKKeyExchangeMode{PSKModePlain},
			want:  []byte{0x01, 0x00},
		},
		{
			name:  "正常系：両モード",
			modes: []PSKKeyExchangeMode{PSKModePlain, PSKModeDHE},
			want:  []byte{0x02, 0x00, 0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PSKKeyExchangeModes{Modes: tt.modes}
			got := p.MarshalPayload()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("PSKKeyExchangeModes.MarshalPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPSKKeyExchangeModes_Unmarshal(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantModes   []PSKKeyExchangeMode
	}{
		{
			name:        "正常系：psk_dhe_keのみ",
			payload:     []byte{0x01, 0x01},
			wantSuccess: true,
			wantModes:   []PSKKeyExchangeMode{PSKModeDHE},
		},
		{
			name:        "正常系：両モード",
			payload:     []byte{0x02, 0x00, 0x01},
			wantSuccess: true,
			wantModes:   []PSKKeyExchangeMode{PSKModePlain, PSKModeDHE},
		},
		{
			name:        "異常系：空のリスト",
			payload:     []byte{0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：データ不足",
			payload:     []byte{0x02, 0x01},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PSKKeyExchangeModes{}
			err := p.Unmarshal(tt.payload)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("PSKKeyExchangeModes.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if len(p.Modes) != len(tt.wantModes) {
				t.Errorf("len(Modes) = %d, want %d", len(p.Modes), len(tt.wantModes))
				return
			}
			for i, m := range p.Modes {
				if m != tt.wantModes[i] {
					t.Errorf("Modes[%d] = %v, want %v", i, m, tt.wantModes[i])
				}
			}
		})
	}
}

func TestNewPskKeyExchangeModesExtension(t *testing.T) {
	ext := NewPskKeyExchangeModesExtension()
	if ext.Type != protocol.ExtPSKKeyExchangeModes {
		t.Errorf("Type = %v, want %v", ext.Type, protocol.ExtPSKKeyExchangeModes)
	}
}

func TestParsePSKKeyExchangeModes(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantCount   int
	}{
		{
			name:        "正常系：1モード",
			payload:     []byte{0x01, 0x01},
			wantSuccess: true,
			wantCount:   1,
		},
		{
			name:        "正常系：2モード",
			payload:     []byte{0x02, 0x00, 0x01},
			wantSuccess: true,
			wantCount:   2,
		},
		{
			name:        "異常系：空",
			payload:     []byte{0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：データ不足",
			payload:     []byte{0x03, 0x00, 0x01},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modes, ok := ParsePSKKeyExchangeModes(tt.payload)
			if ok != tt.wantSuccess {
				t.Errorf("ParsePSKKeyExchangeModes() ok = %v, want %v", ok, tt.wantSuccess)
				return
			}
			if tt.wantSuccess && len(modes) != tt.wantCount {
				t.Errorf("len(modes) = %d, want %d", len(modes), tt.wantCount)
			}
		})
	}
}

func TestPSKKeyExchangeModes_RoundTrip(t *testing.T) {
	original := &PSKKeyExchangeModes{
		Modes: []PSKKeyExchangeMode{PSKModePlain, PSKModeDHE},
	}

	payload := original.MarshalPayload()

	parsed := &PSKKeyExchangeModes{}
	if err := parsed.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.Modes) != len(original.Modes) {
		t.Fatalf("len mismatch: got %d, want %d", len(parsed.Modes), len(original.Modes))
	}
	for i := range original.Modes {
		if parsed.Modes[i] != original.Modes[i] {
			t.Errorf("Modes[%d] = %v, want %v", i, parsed.Modes[i], original.Modes[i])
		}
	}
}

func TestPSKKeyExchangeMode_Constants(t *testing.T) {
	if PSKModePlain != 0 {
		t.Errorf("PSKModePlain = %d, want 0", PSKModePlain)
	}
	if PSKModeDHE != 1 {
		t.Errorf("PSKModeDHE = %d, want 1", PSKModeDHE)
	}
}
