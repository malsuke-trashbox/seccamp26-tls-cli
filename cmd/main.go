package main

import (
	"net"
	"os"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/appdata"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/utils"
)

const defaultServerName = "www.example.com"

func main() {
	tcp, err := (&net.Dialer{}).Dial("tcp", defaultServerName+":443")
	if err != nil {
		panic(err)
	}
	defer tcp.Close()

	privateKey, publicKey, err := key.GenerateX25519KeyPair()
	if err != nil {
		panic(err)
	}

	clientHelloRecord, err := NewClientHelloRecord(publicKey)
	if err != nil {
		panic(err)
	}

	if _, err := tcp.Write(clientHelloRecord.Marshal()); err != nil {
		panic(err)
	}

	var buf [4096]byte
	n, err := tcp.Read(buf[:])
	if err != nil {
		panic(err)
	}

	plaintextRecords, ciphertextRecords, err := utils.ParseRecords(buf[:n])
	if err != nil {
		panic(err)
	}

	serverHello, err := utils.ParseServerHelloFromRecords(plaintextRecords)
	if err != nil {
		panic(err)
	}

	serverShare, err := serverHello.ServerShare()
	if err != nil {
		panic(err)
	}

	sharedSecret, err := key.ComputeSharedKey(privateKey, serverShare.Data)
	if err != nil {
		panic(err)
	}

	messages, err := utils.CollectHandshakeMessages(plaintextRecords)
	if err != nil {
		panic(err)
	}

	serverHelloMessage, ok := utils.FindFirstHandshakeMessage(messages, protocol.TypeServerHello)
	if !ok {
		panic(utils.ErrServerHelloNotFound)
	}

	handshakeSecrets, err := key.DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret, clientHelloRecord.Payload, serverHelloMessage)
	if err != nil {
		panic(err)
	}

	decryptedServerHandshakeRecords, err := utils.DecodeTLSCiphertextRecordsWithChaCha20Poly1305(
		ciphertextRecords,
		handshakeSecrets.ServerHandshakeKey,
		handshakeSecrets.ServerHandshakeIV,
		0,
	)
	if err != nil {
		panic(err)
	}

	serverEncryptedHandshakeMessages, err := utils.ConcatHandshakeMessages(decryptedServerHandshakeRecords)
	if err != nil {
		panic(err)
	}

	sessionKeys, err := key.DeriveTLS13ChaCha20ClientSessionKeys(
		sharedSecret,
		clientHelloRecord.Payload,
		serverHelloMessage,
		serverEncryptedHandshakeMessages,
	)
	if err != nil {
		panic(err)
	}

	finishedHandshake, err := handshake.NewHandshake(&handshake.Finished{VerifyData: sessionKeys.ClientFinishedVerifyData})
	if err != nil {
		panic(err)
	}

	finishedRecord, err := utils.EncryptTLS13Record(
		sessionKeys.ClientHandshakeKey,
		sessionKeys.ClientHandshakeIV,
		0,
		protocol.Handshake,
		finishedHandshake.Marshal(),
	)
	if err != nil {
		panic(err)
	}
	if _, err := tcp.Write(finishedRecord.Marshal()); err != nil {
		panic(err)
	}

	httpRequest := []byte("GET / HTTP/1.1\r\nHost: " + defaultServerName + "\r\nConnection: close\r\n\r\n")
	applicationData := (&appdata.ApplicationData{Data: httpRequest}).Marshal()
	applicationDataRecord, err := utils.EncryptTLS13Record(
		sessionKeys.ClientApplicationKey,
		sessionKeys.ClientApplicationIV,
		0,
		protocol.ApplicationData,
		applicationData,
	)
	if err != nil {
		panic(err)
	}
	if _, err := tcp.Write(applicationDataRecord.Marshal()); err != nil {
		panic(err)
	}

	responseApplicationData, err := utils.ReadServerApplicationData(tcp, sessionKeys.ServerApplicationKey, sessionKeys.ServerApplicationIV)
	if err != nil {
		panic(err)
	}

	if len(responseApplicationData) > 0 {
		if _, err := os.Stdout.Write(responseApplicationData); err != nil {
			panic(err)
		}
	}
}
