package record

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func TestNewTLSPlaintext(t *testing.T) {
	tests := []struct {
		name         string
		ContentType  protocol.ContentType
		payload      []byte
		want         *TLSPlaintext
		expectingErr bool
	}{
		{
			name:        "正常系：ハンドシェイクメッセージ",
			ContentType: protocol.Handshake,
			payload:     []byte("hello"),
			want: &TLSPlaintext{
				Type:    protocol.Handshake,
				Version: protocol.TLS_VERSION_1_2,
				Length:  5,
				Payload: []byte("hello"),
			},
			expectingErr: false,
		},
		{
			name:        "正常系：アプリケーションデータ",
			ContentType: protocol.ApplicationData,
			payload:     []byte{0x01, 0x02, 0x03},
			want: &TLSPlaintext{
				Type:    protocol.ApplicationData,
				Version: protocol.TLS_VERSION_1_2,
				Length:  3,
				Payload: []byte{0x01, 0x02, 0x03},
			},
			expectingErr: false,
		},
		{
			name:         "異常系：ペイロードが大きすぎる",
			ContentType:  protocol.ApplicationData,
			payload:      make([]byte, 16385),
			want:         nil,
			expectingErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTLSPlaintext(tt.ContentType, tt.payload)
			if (err != nil) != tt.expectingErr {
				t.Errorf("NewTLSPlaintext() error = %v, expectingErr %v", err, tt.expectingErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTLSPlaintext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLSPlaintext_Marshal(t *testing.T) {
	tests := []struct {
		name string
		r    *TLSPlaintext
		want []byte
	}{
		{
			name: "正常系：ハンドシェイクメッセージ",
			r: &TLSPlaintext{
				Type:    protocol.Handshake,
				Version: protocol.TLS_VERSION_1_2,
				Length:  12,
				Payload: []byte("hello world!"),
			},
			want: []byte{
				0x16,
				0x03, 0x03,
				0x00, 0x0c,
				'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
			},
		},
		{
			name: "正常系：空のペイロード",
			r: &TLSPlaintext{
				Type:    protocol.Alert,
				Version: protocol.TLS_VERSION_1_2,
				Length:  0,
				Payload: []byte{},
			},
			want: []byte{
				0x15,
				0x03, 0x03,
				0x00, 0x00,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.Marshal(); !bytes.Equal(got, tt.want) {
				t.Errorf("TLSPlaintext.Marshal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTLSPlaintext(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		want         *TLSPlaintext
		expectingErr bool
	}{
		{
			name: "正常系：ハンドシェイクメッセージ",
			data: []byte{
				0x16,
				0x03, 0x03,
				0x00, 0x05,
				't', 'e', 's', 't', '!',
			},
			want: &TLSPlaintext{
				Type:    protocol.Handshake,
				Version: protocol.TLS_VERSION_1_2,
				Length:  5,
				Payload: []byte("test!"),
			},
			expectingErr: false,
		},
		{
			name: "正常系：後続データが存在する場合",
			data: []byte{
				0x17,
				0x03, 0x03,
				0x00, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0xaa, 0xbb, 0xcc,
			},
			want: &TLSPlaintext{
				Type:    protocol.ApplicationData,
				Version: protocol.TLS_VERSION_1_2,
				Length:  4,
				Payload: []byte{0x01, 0x02, 0x03, 0x04},
			},
			expectingErr: false,
		},
		{
			name:         "異常系：データがヘッダーサイズより短い",
			data:         []byte{0x16, 0x03, 0x03, 0x00},
			want:         nil,
			expectingErr: true,
		},
		{
			name:         "異常系：データがLengthフィールドの値より短い",
			data:         []byte{0x16, 0x03, 0x03, 0x00, 0x0a, 0x01, 0x02, 0x03},
			want:         nil,
			expectingErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTLSPlaintext(tt.data)
			if (err != nil) != tt.expectingErr {
				t.Errorf("ParseTLSPlaintext() error = %v, expectingErr %v", err, tt.expectingErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTLSPlaintext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLSPlaintext_RoundTrip(t *testing.T) {
	t.Run("正常系：生成、マーシャリング、パースの一連の処理が正しく行われる", func(t *testing.T) {
		originalPayload := []byte("this is a round trip test")
		originalRecord, err := NewTLSPlaintext(protocol.ApplicationData, originalPayload)
		if err != nil {
			t.Fatalf("NewTLSPlaintext() failed: %v", err)
		}

		marshaledData := originalRecord.Marshal()

		parsedRecord, err := ParseTLSPlaintext(marshaledData)
		if err != nil {
			t.Fatalf("ParseTLSPlaintext() failed: %v", err)
		}

		if !reflect.DeepEqual(originalRecord, parsedRecord) {
			t.Errorf("Round trip failed. Original: %v, Parsed: %v", originalRecord, parsedRecord)
		}
	})
}

func TestTLSInnerPlaintextRoundTrip(t *testing.T) {
	inner := &TLSInnerPlaintext{Content: []byte("hello"), Type: protocol.Handshake, Padding: []byte{0x00, 0x00}}
	parsed, err := ParseTLSInnerPlaintext(inner.Marshal())
	if err != nil {
		t.Fatalf("ParseTLSInnerPlaintext() failed: %v", err)
	}
	if !bytes.Equal(parsed.Content, []byte("hello")) {
		t.Fatalf("Content = %q, want %q", string(parsed.Content), "hello")
	}
	if parsed.Type != protocol.Handshake {
		t.Fatalf("Type = %v, want %v", parsed.Type, protocol.Handshake)
	}
	if !bytes.Equal(parsed.Padding, []byte{0x00, 0x00}) {
		t.Fatalf("Padding = %v, want %v", parsed.Padding, []byte{0x00, 0x00})
	}
}

func TestParseTLSPlaintextRecords(t *testing.T) {
	rec1, err := NewTLSPlaintext(protocol.Handshake, []byte{0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("NewTLSPlaintext(rec1) failed: %v", err)
	}
	rec2, err := NewTLSPlaintext(protocol.Alert, []byte{0x02, 0x00})
	if err != nil {
		t.Fatalf("NewTLSPlaintext(rec2) failed: %v", err)
	}

	raw := append([]byte{}, rec1.Marshal()...)
	raw = append(raw, rec2.Marshal()...)

	records, err := ParseTLSPlaintextRecords(raw)
	if err != nil {
		t.Fatalf("ParseTLSPlaintextRecords() failed: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	if records[0].Type != protocol.Handshake {
		t.Fatalf("records[0].Type = %v, want %v", records[0].Type, protocol.Handshake)
	}
	if records[1].Type != protocol.Alert {
		t.Fatalf("records[1].Type = %v, want %v", records[1].Type, protocol.Alert)
	}
}

func TestParseTLSPlaintextRecordsWithRemainder(t *testing.T) {
	rec, err := NewTLSPlaintext(protocol.Handshake, []byte{0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("NewTLSPlaintext() failed: %v", err)
	}

	raw := append([]byte{}, rec.Marshal()...)
	raw = append(raw, rec.Marshal()...)
	raw = raw[:len(raw)-2]

	records, remain, err := ParseTLSPlaintextRecordsWithRemainder(raw)
	if err != nil {
		t.Fatalf("ParseTLSPlaintextRecordsWithRemainder() failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if len(remain) != len(rec.Marshal())-2 {
		t.Fatalf("len(remain) = %d, want %d", len(remain), len(rec.Marshal())-2)
	}
}

func TestParseTLSPlaintextRecords_IncompleteFails(t *testing.T) {
	rec, err := NewTLSPlaintext(protocol.Handshake, []byte{0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("NewTLSPlaintext() failed: %v", err)
	}

	raw := rec.Marshal()
	raw = raw[:len(raw)-1]

	_, err = ParseTLSPlaintextRecords(raw)
	if err == nil {
		t.Fatal("ParseTLSPlaintextRecords() should fail on incomplete record")
	}
}

func TestParseTLSCiphertextRecords(t *testing.T) {
	rec, err := NewTLSPlaintext(protocol.ApplicationData, []byte{0xaa, 0xbb})
	if err != nil {
		t.Fatalf("NewTLSPlaintext() failed: %v", err)
	}

	records, err := ParseTLSCiphertextRecords(rec.Marshal())
	if err != nil {
		t.Fatalf("ParseTLSCiphertextRecords() failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].Type != protocol.ApplicationData {
		t.Fatalf("records[0].Type = %v, want %v", records[0].Type, protocol.ApplicationData)
	}
}
