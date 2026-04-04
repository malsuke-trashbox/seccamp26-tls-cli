package extensions

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestCookie_Type(t *testing.T) {
	c := &Cookie{}
	if c.Type() != protocol.ExtCookie {
		t.Errorf("Cookie.Type() = %v, want %v", c.Type(), protocol.ExtCookie)
	}
}

func TestCookie_MarshalPayload(t *testing.T) {
	tests := []struct {
		name   string
		cookie []byte
		want   []byte
	}{
		{
			name:   "正常系：短いクッキー",
			cookie: []byte{0x01, 0x02, 0x03, 0x04},
			want:   []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:   "正常系：長いクッキー",
			cookie: make([]byte, 256),
			want: func() []byte {
				d := []byte{0x01, 0x00} // length: 256
				d = append(d, make([]byte, 256)...)
				return d
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cookie{Cookie: tt.cookie}
			got := c.MarshalPayload()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Cookie.MarshalPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCookie_Unmarshal(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
		wantCookie  []byte
	}{
		{
			name:        "正常系：短いクッキー",
			payload:     []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04},
			wantSuccess: true,
			wantCookie:  []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name:        "異常系：空のクッキー",
			payload:     []byte{0x00, 0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：データ不足",
			payload:     []byte{0x00, 0x04, 0x01, 0x02},
			wantSuccess: false,
		},
		{
			name:        "異常系：余分なデータ",
			payload:     []byte{0x00, 0x02, 0x01, 0x02, 0xff},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cookie{}
			err := c.Unmarshal(tt.payload)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("Cookie.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if tt.wantSuccess && !bytes.Equal(c.Cookie, tt.wantCookie) {
				t.Errorf("Cookie.Cookie = %v, want %v", c.Cookie, tt.wantCookie)
			}
		})
	}
}

func TestParseCookie(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantSuccess bool
	}{
		{
			name:        "正常系",
			payload:     []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04},
			wantSuccess: true,
		},
		{
			name:        "異常系：空",
			payload:     []byte{0x00, 0x00},
			wantSuccess: false,
		},
		{
			name:        "異常系：余分なデータ",
			payload:     []byte{0x00, 0x01, 0x01, 0xff},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := ParseCookie(tt.payload)
			if ok != tt.wantSuccess {
				t.Errorf("ParseCookie() ok = %v, want %v", ok, tt.wantSuccess)
			}
		})
	}
}

func TestCookie_RoundTrip(t *testing.T) {
	original := &Cookie{
		Cookie: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}

	payload := original.MarshalPayload()

	parsed := &Cookie{}
	if err := parsed.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !bytes.Equal(parsed.Cookie, original.Cookie) {
		t.Errorf("Cookie = %v, want %v", parsed.Cookie, original.Cookie)
	}
}

func TestParseCookie_CreatesCopy(t *testing.T) {
	payload := []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04}
	originalPayload := make([]byte, len(payload))
	copy(originalPayload, payload)

	cookie, ok := ParseCookie(payload)
	if !ok {
		t.Fatal("ParseCookie failed")
	}

	// Modify original payload
	payload[3] = 0xff

	// Cookie should not be affected
	if cookie[1] == 0xff {
		t.Error("ParseCookie should create a copy")
	}
}
