package main

import (
	"fmt"
	"net"
	"os"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/utils"
)

const defaultServerName = "www.example.com"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	conn, err := (&net.Dialer{}).Dial("tcp", defaultServerName+":443")
	if err != nil {
		return err
	}
	defer conn.Close()

	// TLS 1.3 のハンドシェイクの実施
	sessionKeys, err := doHandshake(conn)
	if err != nil {
		return err
	}

	// Application Data の送受信
	applicationDataRecord, err := BuildApplicationDataRecord(sessionKeys, 0)
	if err != nil {
		return err
	}
	if _, err := conn.Write(applicationDataRecord.Marshal()); err != nil {
		return err
	}

	responseApplicationData, _, err := utils.ReadServerApplicationData(conn, sessionKeys.ServerApplicationKey, sessionKeys.ServerApplicationIV)
	if err != nil {
		return err
	}

	if len(responseApplicationData) > 0 {
		if _, err := os.Stdout.Write(responseApplicationData); err != nil {
			return err
		}
	}

	return nil
}
