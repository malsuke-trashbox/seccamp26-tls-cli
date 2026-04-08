package main

import (
	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/appdata"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/utils"
)

func BuildApplicationDataRecord(sessionKeys *key.TLS13ChaCha20ClientSessionKeys, seq uint64) (record.TLSCiphertext, error) {
	// step1: 送信したいHTTPリクエストを作る
	httpRequest := []byte("GET / HTTP/1.1\r\nHost: " + defaultServerName + "\r\nConnection: close\r\n\r\n")

	// step2: HTTPバイト列をTLSのApplicationDataメッセージに包む
	applicationData := (&appdata.ApplicationData{Data: httpRequest}).Marshal()

	// step3: TLSInnerPlaintextを作る（content + content_type）
	innerPlaintext := utils.BuildTLSInnerPlaintext(protocol.ApplicationData, applicationData)

	// step4: 暗号化後の長さを見込んだTLSCiphertextレコード枠を作る
	ciphertextRecord := utils.NewTLS13ApplicationDataCiphertextRecordForInnerPlaintext(innerPlaintext)

	// step5: client_application_traffic_secret から導いた鍵/IVで中身を暗号化する
	encryptedPayload, err := utils.EncryptTLS13RecordPayload(
		sessionKeys.ClientApplicationKey,
		sessionKeys.ClientApplicationIV,
		seq,
		ciphertextRecord.Header(),
		innerPlaintext,
	)
	if err != nil {
		return record.TLSCiphertext{}, err
	}

	// step6: 暗号文をレコードにセットして完成
	ciphertextRecord.Payload = encryptedPayload
	ciphertextRecord.Length = uint16(len(encryptedPayload))

	return ciphertextRecord, nil
}
