package handshake

import (
	"bytes"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestFinished_Type(t *testing.T) {
	f := &Finished{}
	if f.Type() != protocol.TypeFinished {
		t.Errorf("Finished.Type() = %v, want %v", f.Type(), protocol.TypeFinished)
	}
}

func TestFinished_Marshal(t *testing.T) {
	tests := []struct {
		name       string
		verifyData []byte
		want       []byte
	}{
		{
			name:       "正常系：32バイトのverify_data",
			verifyData: make([]byte, 32),
			want:       make([]byte, 32),
		},
		{
			name:       "正常系：特定のデータ",
			verifyData: []byte{0x01, 0x02, 0x03, 0x04},
			want:       []byte{0x01, 0x02, 0x03, 0x04},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finished{VerifyData: tt.verifyData}
			if got := f.Marshal(); !bytes.Equal(got, tt.want) {
				t.Errorf("Finished.Marshal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFinished_Unmarshal(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		wantSuccess    bool
		wantVerifyData []byte
	}{
		{
			name: "正常系：32バイトのverify_data",
			data: func() []byte {
				verifyData := make([]byte, 32)
				for i := range verifyData {
					verifyData[i] = byte(i)
				}
				// Handshake header
				d := []byte{byte(protocol.TypeFinished)}
				d = append(d, 0x00, 0x00, 0x20) // length: 32
				d = append(d, verifyData...)
				return d
			}(),
			wantSuccess: true,
			wantVerifyData: func() []byte {
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				return data
			}(),
		},
		{
			name: "正常系：小さいverify_data",
			data: func() []byte {
				d := []byte{byte(protocol.TypeFinished)}
				d = append(d, 0x00, 0x00, 0x04) // length: 4
				d = append(d, 0xaa, 0xbb, 0xcc, 0xdd)
				return d
			}(),
			wantSuccess:    true,
			wantVerifyData: []byte{0xaa, 0xbb, 0xcc, 0xdd},
		},
		{
			name:        "異常系：データが短すぎる",
			data:        []byte{},
			wantSuccess: false,
		},
		{
			name: "異常系：verify_dataの後に余分なデータ",
			data: func() []byte {
				d := []byte{byte(protocol.TypeFinished)}
				d = append(d, 0x00, 0x00, 0x02) // length: 2
				d = append(d, 0x01, 0x02)
				d = append(d, 0xff) // extra byte
				return d
			}(),
			wantSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finished{}
			err := f.Unmarshal(tt.data)
			gotSuccess := err == nil
			if gotSuccess != tt.wantSuccess {
				t.Errorf("Finished.Unmarshal() success = %v, want %v (err=%v)", gotSuccess, tt.wantSuccess, err)
				return
			}
			if !tt.wantSuccess {
				return
			}
			if !bytes.Equal(f.VerifyData, tt.wantVerifyData) {
				t.Errorf("Finished.VerifyData = %v, want %v", f.VerifyData, tt.wantVerifyData)
			}
		})
	}
}

func TestFinished_RoundTrip(t *testing.T) {
	original := &Finished{
		VerifyData: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	// Marshal
	marshaled := original.Marshal()

	// Create full message with header for unmarshal
	fullMsg := []byte{byte(protocol.TypeFinished)}
	fullMsg = append(fullMsg, 0x00, 0x00, byte(len(marshaled)))
	fullMsg = append(fullMsg, marshaled...)

	// Unmarshal
	parsed := &Finished{}
	if err := parsed.Unmarshal(fullMsg); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !bytes.Equal(original.VerifyData, parsed.VerifyData) {
		t.Errorf("RoundTrip failed: got %v, want %v", parsed.VerifyData, original.VerifyData)
	}
}

func TestFinished_VerifyDataCopy(t *testing.T) {
	// Test that Unmarshal creates a copy of verify data
	verifyData := []byte{0x01, 0x02, 0x03, 0x04}
	data := []byte{byte(protocol.TypeFinished), 0x00, 0x00, 0x04}
	data = append(data, verifyData...)

	f := &Finished{}
	if err := f.Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Modify original data
	verifyData[0] = 0xff

	// Verify that Finished.VerifyData is not affected
	if f.VerifyData[0] == 0xff {
		t.Error("VerifyData should be a copy, not a reference")
	}
}
