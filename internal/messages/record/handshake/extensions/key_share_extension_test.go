package extensions

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestKeyShareClient_Type(t *testing.T) {
	ks := &KeyShareExtension{}
	if ks.Type() != protocol.ExtKeyShare {
		t.Errorf("KeyShareClient.Type() = %v, want %v", ks.Type(), protocol.ExtKeyShare)
	}
}

func TestKeyShareClient_MarshalPayload(t *testing.T) {
	tests := []struct {
		name      string
		keyShares []KeyShare
	}{
		{
			name: "正常系：1つのKeyShare",
			keyShares: []KeyShare{
				{Group: protocol.X25519, Data: make([]byte, 32)},
			},
		},
		{
			name: "正常系：複数のKeyShare",
			keyShares: []KeyShare{
				{Group: protocol.X25519, Data: make([]byte, 32)},
				{Group: protocol.CurveP256, Data: make([]byte, 65)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &KeyShareExtension{KeyShares: tt.keyShares}
			payload := ks.MarshalPayload()
			if len(payload) == 0 {
				t.Error("MarshalPayload() returned empty payload")
			}
		})
	}
}

func TestKeyShareClient_Unmarshal(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantCount   int
	}{
		{
			name: "正常系：1つのKeyShare",
			payload: func() []byte {
				key := make([]byte, 32)
				d := []byte{0x00, byte(2 + 2 + len(key))} // list length
				d = append(d, 0x00, 0x1d)                  // X25519
				d = append(d, 0x00, byte(len(key)))        // key length
				d = append(d, key...)
				return d
			}(),
			wantSuccess: true,
			wantCount:   1,
		},
		{
			name:        "異常系：空のリスト",
			payload:     []byte{0x00, 0x00},
			wantSuccess: true,
			wantCount:   0,
		},
		{
			name:        "異常系：データ不足",
			payload:     []byte{0x00},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &KeyShareExtension{}
			err := ks.Unmarshal(tt.payload)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("KeyShareClient.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if tt.wantSuccess && len(ks.KeyShares) != tt.wantCount {
				t.Errorf("len(KeyShares) = %d, want %d", len(ks.KeyShares), tt.wantCount)
			}
		})
	}
}

func TestNewKeyShareExtension(t *testing.T) {
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}

	ext := NewKeyShareExtension(publicKey)
	if ext.Type != protocol.ExtKeyShare {
		t.Errorf("Type = %v, want %v", ext.Type, protocol.ExtKeyShare)
	}
}

func TestParseKeyShareClient(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantCount   int
		wantGroup   protocol.CurveID
	}{
		{
			name: "正常系：X25519",
			payload: func() []byte {
				key := make([]byte, 32)
				d := []byte{0x00, byte(2 + 2 + len(key))}
				d = append(d, 0x00, 0x1d) // X25519
				d = append(d, 0x00, byte(len(key)))
				d = append(d, key...)
				return d
			}(),
			wantSuccess: true,
			wantCount:   1,
			wantGroup:   protocol.X25519,
		},
		{
			name: "正常系：P-256",
			payload: func() []byte {
				key := make([]byte, 65)
				d := []byte{0x00, byte(2 + 2 + len(key))}
				d = append(d, 0x00, 0x17) // P-256
				d = append(d, 0x00, byte(len(key)))
				d = append(d, key...)
				return d
			}(),
			wantSuccess: true,
			wantCount:   1,
			wantGroup:   protocol.CurveP256,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, ok := ParseKeyShareClient(tt.payload)
			if ok != tt.wantSuccess {
				t.Errorf("ParseKeyShareClient() ok = %v, want %v", ok, tt.wantSuccess)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if len(shares) != tt.wantCount {
				t.Errorf("len(shares) = %d, want %d", len(shares), tt.wantCount)
				return
			}
			if tt.wantCount > 0 && shares[0].Group != tt.wantGroup {
				t.Errorf("shares[0].Group = %v, want %v", shares[0].Group, tt.wantGroup)
			}
		})
	}
}

func TestParseKeyShareServer(t *testing.T) {
	tests := []struct {
		name            string
		payload         []byte
		wantSuccess     bool
		wantGroup       protocol.CurveID
		wantSelectedGrp protocol.CurveID
	}{
		{
			name: "正常系：KeyShare",
			payload: func() []byte {
				key := make([]byte, 32)
				d := []byte{0x00, 0x1d} // X25519
				d = append(d, 0x00, byte(len(key)))
				d = append(d, key...)
				return d
			}(),
			wantSuccess: true,
			wantGroup:   protocol.X25519,
		},
		{
			name:            "正常系：HelloRetryRequest（グループ選択のみ）",
			payload:         []byte{0x00, 0x1d}, // X25519
			wantSuccess:     true,
			wantSelectedGrp: protocol.X25519,
		},
		{
			name: "異常系：余分なデータ",
			payload: func() []byte {
				key := make([]byte, 32)
				d := []byte{0x00, 0x1d}
				d = append(d, 0x00, byte(len(key)))
				d = append(d, key...)
				d = append(d, 0xff) // extra
				return d
			}(),
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			share, selectedGroup, ok := ParseKeyShareServer(tt.payload)
			if ok != tt.wantSuccess {
				t.Errorf("ParseKeyShareServer() ok = %v, want %v", ok, tt.wantSuccess)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if tt.wantSelectedGrp != 0 {
				if selectedGroup != tt.wantSelectedGrp {
					t.Errorf("selectedGroup = %v, want %v", selectedGroup, tt.wantSelectedGrp)
				}
			} else {
				if share.Group != tt.wantGroup {
					t.Errorf("share.Group = %v, want %v", share.Group, tt.wantGroup)
				}
			}
		})
	}
}

func TestKeyShareClient_RoundTrip(t *testing.T) {
	original := &KeyShareExtension{
		KeyShares: []KeyShare{
			{Group: protocol.X25519, Data: []byte{0x01, 0x02, 0x03, 0x04}},
		},
	}

	payload := original.MarshalPayload()

	parsed := &KeyShareExtension{}
	if err := parsed.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.KeyShares) != len(original.KeyShares) {
		t.Fatalf("len mismatch: got %d, want %d", len(parsed.KeyShares), len(original.KeyShares))
	}
	if parsed.KeyShares[0].Group != original.KeyShares[0].Group {
		t.Errorf("Group = %v, want %v", parsed.KeyShares[0].Group, original.KeyShares[0].Group)
	}
	if !bytes.Equal(parsed.KeyShares[0].Data, original.KeyShares[0].Data) {
		t.Errorf("Data = %v, want %v", parsed.KeyShares[0].Data, original.KeyShares[0].Data)
	}
}
