package main

import (
	"crypto/ecdh"
	"fmt"
	"net"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/cert"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/utils"
)

// doHandshake performs the TLS 1.3 client handshake on conn and returns the
// derived session keys for application-data traffic. All failures are returned
// as errors so the caller can decide how to report them.
func doHandshake(conn net.Conn) (*key.TLS13ChaCha20ClientSessionKeys, error) {
	/**
	 * step1: 鍵交換で利用する共通鍵と秘密鍵を生成する
	 * key.GenerateX25519KeyPair() を使う
	 */
	privateKey, publicKey, err := key.GenerateX25519KeyPair()
	if err != nil {
		return nil, err
	}

	/**
	 * step2: ClientHello レコードを生成し、サーバに送信する
	 */
	clientHelloRecord, err := NewClientHelloRecord(publicKey)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(clientHelloRecord.Marshal()); err != nil {
		return nil, fmt.Errorf("tls: failed to send client hello: %w", err)
	}

	/**
	 * step3: サーバの第1フライトを読み取る
	 * 証明書チェーンを含むフライトは複数の TCP セグメントに分割されて届くため、
	 * Finished を復号できるまで（= フライトが揃うまで）読み続ける。
	 * アラートが来た場合は ReadServerHandshakeFlight がエラーを返す。
	 */
	flight, err := utils.ReadServerHandshakeFlight(conn, func(accumulated []byte) bool {
		return utils.ServerHandshakeFlightComplete(accumulated, privateKey, clientHelloRecord.Payload)
	})
	if err != nil {
		return nil, err
	}

	/**
	 * step4: 受け取ったバイト列をTLSレコードにパースする
	 */
	plaintextRecords, ciphertextRecords, err := utils.ParseRecords(flight)
	if err != nil {
		return nil, err
	}

	/**
	 * step5: ServerFlightから送られてくるTLSPlaintextから扱いやすいように、ServerHelloをパースする
	 * ついでに、ServerHelloを含むHandshakeメッセージのバイト列も取得する
	 */

	serverHello, serverHelloMessage, err := utils.ParseTLS13ServerHelloAndMessage(plaintextRecords)
	if err != nil {
		return nil, err
	}

	// step6: 共通鍵を導出する
	sharedSecret, err := utils.DeriveTLS13SharedSecretFromServerHello(privateKey, serverHello)
	if err != nil {
		return nil, err
	}

	// step7: 復号に必要なサーバHandshake鍵を導出する
	serverHandshakeSecrets, err := key.DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret, clientHelloRecord.Payload, serverHelloMessage)
	if err != nil {
		return nil, err
	}

	// step8: サーバの暗号化Handshakeレコードを復号し、Handshakeメッセージをパースする
	_, serverCertificate, serverCertificateVerify, serverFinished, serverHandshakePlaintextRecords, err := utils.DecodeAndParseServerTLS13HandshakeMessagesWithChaCha20Poly1305(
		ciphertextRecords,
		serverHandshakeSecrets.ServerHandshakeKey,
		serverHandshakeSecrets.ServerHandshakeIV,
		0,
	)
	if err != nil {
		return nil, err
	}

	// step9: サーバ証明書チェーンを OS 非依存ルート証明書 (certifi) で検証する
	leafCertificate, _, err := cert.VerifyServerCertificateChainWithCertifi(serverCertificate, defaultServerName)
	if err != nil {
		return nil, err
	}

	// step10: CertificateVerify 署名を検証して、サーバ秘密鍵の正当性を確認する
	transcriptBeforeCertificateVerify, err := utils.BuildTLS13HandshakeTranscriptBeforeMessageType(
		clientHelloRecord.Payload,
		serverHelloMessage,
		serverHandshakePlaintextRecords,
		protocol.TypeCertificateVerify,
	)
	if err != nil {
		return nil, err
	}

	if err := cert.VerifyTLS13ServerCertificateVerify(
		leafCertificate,
		serverCertificateVerify.SignatureAlgorithm,
		serverCertificateVerify.Signature,
		transcriptBeforeCertificateVerify,
	); err != nil {
		return nil, err
	}

	// step11: Server Finished を検証して、復号したハンドシェイク完全性を確認する
	transcriptBeforeServerFinished, err := utils.BuildTLS13HandshakeTranscriptBeforeMessageType(
		clientHelloRecord.Payload,
		serverHelloMessage,
		serverHandshakePlaintextRecords,
		protocol.TypeFinished,
	)
	if err != nil {
		return nil, err
	}

	if err := key.VerifyTLS13ServerFinished(
		serverHandshakeSecrets.ServerHandshakeTrafficSecret,
		transcriptBeforeServerFinished,
		serverFinished.VerifyData,
	); err != nil {
		return nil, err
	}

	// step12: ClientFinished と ApplicationData 通信用のセッション鍵を導出する
	clientSessionKeys, err := key.DeriveTLS13ChaCha20ClientSessionKeys(
		sharedSecret,
		clientHelloRecord.Payload,
		serverHelloMessage,
		serverHandshakePlaintextRecords,
	)
	if err != nil {
		return nil, err
	}

	// step13: ClientFinished レコードを生成し、サーバに送信する
	finishedRecord, err := utils.BuildClientFinishedRecord(clientSessionKeys, 0)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(finishedRecord.Marshal()); err != nil {
		return nil, fmt.Errorf("tls: failed to send client finished: %w", err)
	}

	return clientSessionKeys, nil
}

/**
 * need implementation
 */
func NewClientHelloRecord(pub *ecdh.PublicKey) (*record.TLSPlaintext, error) {
	random, err := key.GenerateRandom32Bytes()
	if err != nil {
		return nil, err
	}

	hs, err := handshake.NewHandshake(&handshake.ClientHello{
		/** ここを実装する */
		ProtocolVersion:          protocol.TLS_VERSION_1_2,
		Random:                   random,
		LegacySessionID:          []byte{},
		CipherSuites:             []protocol.CipherSuite{protocol.TLS_CHACHA20_POLY1305_SHA256},
		LegacyCompressionMethods: []byte{0x00},
		Extensions: []extensions.Extension{
			extensions.NewServerNameExtension("www.example.com"),
			extensions.NewSupportedVersionsExtension(),
			extensions.NewSupportedGroupsExtension(),
			extensions.NewSignatureAlgorithmsExtension(),
			extensions.NewKeyShareExtension(pub.Bytes()),
		},
	})
	if err != nil {
		return nil, err
	}
	rc, err := record.NewTLSPlaintext(
		protocol.Handshake,
		hs.Marshal(),
	)
	if err != nil {
		return nil, err
	}

	return rc, err
}
