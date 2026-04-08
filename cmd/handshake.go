package main

import (
	"crypto/ecdh"
	"errors"
	"net"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake/extensions"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/utils"
)

func do_handshake(conn net.Conn) error {
	/**
	 * step1: 鍵交換で利用する共通鍵と秘密鍵を生成する
	 * key.GenerateX25519KeyPair() を使う
	 */
	privateKey, publicKey, err := key.GenerateX25519KeyPair()
	if err != nil {
		panic(err)
	}

	/**
	 * step2: ClientHello レコードを生成し、サーバに送信する
	 */
	clientHelloRecord, err := NewClientHelloRecord(publicKey)
	if err != nil {
		panic(err)
	}

	if _, err := conn.Write(clientHelloRecord.Marshal()); err != nil {
		panic(err)
	}

	/**
	 * step3: バイト列を読み取る
	 * アラートが来た場合はエラーにして終了
	 */
	var buf [4096]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		panic(err)
	}
	if n > 0 && protocol.ContentType(buf[0]) == protocol.Alert {
		panic(errors.New("tls: alert record received"))
	}

	/**
	 * step4: 受け取ったバイト列をTLSレコードにパースする
	 */
	plaintextRecords, ciphertextRecords, err := utils.ParseRecords(buf[:n])
	if err != nil {
		panic(err)
	}

	/**
	 * step5: ServerFlightから送られてくるTLSPlaintextから扱いやすいように、ServerHelloをパースする
	 * ついでに、ServerHelloを含むHandshakeメッセージのバイト列も取得する
	 */

	serverHello, serverHelloMessage, err := utils.ParseTLS13ServerHelloAndMessage(plaintextRecords)
	if err != nil {
		panic(err)
	}

	// step6: 共通鍵を導出する
	sharedSecret, err := utils.DeriveTLS13SharedSecretFromServerHello(privateKey, serverHello)
	if err != nil {
		panic(err)
	}

	// step7: 復号に必要なサーバHandshake鍵を導出する
	serverHandshakeSecrets, err := key.DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret, clientHelloRecord.Payload, serverHelloMessage)
	if err != nil {
		panic(err)
	}

	// step8: サーバの暗号化Handshakeレコードを復号し、Handshakeメッセージをパースする
	_, _, _, serverFinished, serverHandshakePlaintextRecords, err := utils.DecodeAndParseServerTLS13HandshakeMessagesWithChaCha20Poly1305(
		ciphertextRecords,
		serverHandshakeSecrets.ServerHandshakeKey,
		serverHandshakeSecrets.ServerHandshakeIV,
		0,
	)
	if err != nil {
		panic(err)
	}
	if serverFinished == nil {
		panic(utils.ErrServerFinishedNotFound)
	}

	// step9: ClientFinished と ApplicationData 通信用のセッション鍵を導出する
	clientSessionKeys, err := key.DeriveTLS13ChaCha20ClientSessionKeys(
		sharedSecret,
		clientHelloRecord.Payload,
		serverHelloMessage,
		serverHandshakePlaintextRecords,
	)
	if err != nil {
		panic(err)
	}
	keyState = *clientSessionKeys

	// step10: ClientFinished レコードを生成し、サーバに送信する
	finishedRecord, err := utils.BuildClientFinishedRecord(&keyState, 0)
	if err != nil {
		panic(err)
	}
	if _, err := conn.Write(finishedRecord.Marshal()); err != nil {
		panic(err)
	}

	return nil
}

/**
 * need implementation
 */
func NewClientHelloRecord(pub *ecdh.PublicKey) (*record.TLSPlaintext, error) {
	hs, err := handshake.NewHandshake(&handshake.ClientHello{
		/** ここを実装する */
		ProtocolVersion:          protocol.TLS_VERSION_1_2,
		Random:                   utils.GenerateRandom32Bytes(),
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
