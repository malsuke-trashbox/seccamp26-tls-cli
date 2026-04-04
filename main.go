package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/cert"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/parser"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

const defaultServerName = "www.example.com"

func main() {
	serverName := os.Getenv("TLS_SERVER_NAME")
	if serverName == "" {
		serverName = defaultServerName
	}

	random, err := key.GenerateRandom32Bytes()
	if err != nil {
		panic(err)
	}

	privateKey, publicKey, err := key.GenerateX25519KeyPair()
	if err != nil {
		panic(err)
	}

	clientHelloRecord, err := parser.NewDefaultClientHelloRecord(random, serverName, publicKey.Bytes())
	if err != nil {
		panic(err)
	}

	conn, err := parser.DialTCP(serverName, parser.DefaultDialTimeout)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	records, err := parser.ExchangeClientHello(conn, clientHelloRecord, parser.DefaultReadBufferSize)
	if err != nil {
		panic(err)
	}

	slog.Info("received records", "count", len(records))
	for i, summary := range parser.DescribeRecords(records) {
		fmt.Printf("record[%d] %s\n", i, summary)
	}

	serverHello, err := parser.ParseServerHelloFromRecords(records)
	if err != nil {
		panic(err)
	}

	fmt.Printf("selected cipher suite: %s\n", serverHello.CipherSuite)
	if version, err := serverHello.SupportedVersion(); err == nil {
		fmt.Printf("supported version: %s\n", version)
	}

	if serverShare, err := serverHello.ServerShare(); err == nil {
		sharedKey, err := key.ComputeSharedKey(privateKey, serverShare.Data)
		if err == nil {
			fmt.Printf("shared key (%d bytes): %s\n", len(sharedKey), key.SharedKeyHex(sharedKey))
		}
	}

	messages, err := parser.CollectHandshakeMessages(records)
	if err != nil {
		return
	}

	certificateMessage, ok := parser.FindFirstHandshakeMessage(messages, protocol.TypeCertificate)
	if !ok {
		return
	}

	certificates, err := cert.ParseX509CertificatesFromHandshakeMessage(certificateMessage)
	if err != nil {
		return
	}

	leaf, err := cert.FirstCertificate(certificates)
	if err != nil {
		return
	}

	info, err := cert.BuildCertificateInfo(leaf)
	if err != nil {
		return
	}

	fmt.Printf("leaf certificate subject: %s\n", info.Subject)
}
