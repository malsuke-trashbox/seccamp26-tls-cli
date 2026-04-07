package main

import (
	"net"
	"os"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/appdata"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/utils"
)

const defaultServerName = "www.example.com"

var keyState key.TLS13ChaCha20ClientSessionKeys = key.TLS13ChaCha20ClientSessionKeys{}

func main() {
	conn, err := (&net.Dialer{}).Dial("tcp", defaultServerName+":443")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// TLS 1.3 のハンドシェイクの実施
	do_handshake(conn)

	// Application Data の送受信
	httpRequest := []byte("GET / HTTP/1.1\r\nHost: " + defaultServerName + "\r\nConnection: close\r\n\r\n")
	applicationData := (&appdata.ApplicationData{Data: httpRequest}).Marshal()
	applicationDataRecord, err := utils.BuildClientApplicationDataRecord(&keyState, 0, applicationData)
	if err != nil {
		panic(err)
	}
	if _, err := conn.Write(applicationDataRecord.Marshal()); err != nil {
		panic(err)
	}

	responseApplicationData, _, err := utils.ReadServerApplicationData(conn, keyState.ServerApplicationKey, keyState.ServerApplicationIV)
	if err != nil {
		panic(err)
	}

	if len(responseApplicationData) > 0 {
		if _, err := os.Stdout.Write(responseApplicationData); err != nil {
			panic(err)
		}
	}
}
