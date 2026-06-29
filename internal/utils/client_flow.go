package utils

import (
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

var ErrServerFinishedNotFound = errors.New("tls: server finished not found in records")

// ServerHandshakeFlightComplete reports whether buf holds a complete TLS 1.3
// server handshake flight: a ServerHello plus the encrypted records up to and
// including the server Finished.
//
// It is intended as the isComplete predicate for ReadServerHandshakeFlight, so
// it reports false (rather than returning an error) for any input that is not
// yet a fully decryptable flight — incomplete records, a missing ServerHello, or
// a Finished that has not arrived yet — letting the read loop fetch more bytes.
func ServerHandshakeFlightComplete(buf []byte, privateKey *ecdh.PrivateKey, clientHelloPayload []byte) bool {
	plaintextRecords, ciphertextRecords, err := ParseRecords(buf)
	if err != nil {
		return false
	}

	sharedSecret, serverHelloMessage, err := DeriveTLS13SharedSecretAndServerHelloMessage(privateKey, plaintextRecords)
	if err != nil {
		return false
	}

	handshakeSecrets, err := key.DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret, clientHelloPayload, serverHelloMessage)
	if err != nil {
		return false
	}

	_, _, _, finished, _, err := DecodeAndParseServerTLS13HandshakeMessagesWithChaCha20Poly1305(
		ciphertextRecords,
		handshakeSecrets.ServerHandshakeKey,
		handshakeSecrets.ServerHandshakeIV,
		0,
	)
	if err != nil {
		return false
	}

	return finished != nil
}

func ParseTLS13ServerHelloAndMessage(
	plaintextRecords []record.TLSPlaintext,
) (handshake.ServerHello, []byte, error) {
	serverHello, err := ParseServerHelloFromRecords(plaintextRecords)
	if err != nil {
		return handshake.ServerHello{}, nil, err
	}

	messages, err := CollectHandshakeMessages(plaintextRecords)
	if err != nil {
		return handshake.ServerHello{}, nil, err
	}

	serverHelloMessage, ok := FindFirstHandshakeMessage(messages, protocol.TypeServerHello)
	if !ok {
		return handshake.ServerHello{}, nil, ErrServerHelloNotFound
	}

	return serverHello, serverHelloMessage, nil
}

func DeriveTLS13SharedSecretFromServerHello(
	privateKey *ecdh.PrivateKey,
	serverHello handshake.ServerHello,
) ([]byte, error) {
	serverShare, err := serverHello.ServerShare()
	if err != nil {
		return nil, err
	}

	return key.ComputeSharedKey(privateKey, serverShare.Data)
}

func DetectTLS13ServerFinishedAndConcatHandshakeMessages(
	records []record.TLSPlaintext,
) ([]byte, *handshake.Finished, error) {
	messages, err := CollectHandshakeMessages(records)
	if err != nil {
		return nil, nil, err
	}

	serverFinishedMessage, ok := FindFirstHandshakeMessage(messages, protocol.TypeFinished)
	if !ok {
		return nil, nil, ErrServerFinishedNotFound
	}

	serverFinished := &handshake.Finished{}
	if err := serverFinished.Unmarshal(serverFinishedMessage); err != nil {
		return nil, nil, err
	}

	allHandshakeMessages, err := ConcatHandshakeMessages(records)
	if err != nil {
		return nil, nil, err
	}

	return allHandshakeMessages, serverFinished, nil
}

func BuildTLS13HandshakeTranscriptBeforeMessageType(
	clientHelloMessage []byte,
	serverHelloMessage []byte,
	serverHandshakeRecords []record.TLSPlaintext,
	stopType protocol.HandshakeType,
) ([]byte, error) {
	messages, err := CollectHandshakeMessages(serverHandshakeRecords)
	if err != nil {
		return nil, err
	}

	transcript := make([]byte, 0, len(clientHelloMessage)+len(serverHelloMessage))
	transcript = append(transcript, clientHelloMessage...)
	transcript = append(transcript, serverHelloMessage...)

	foundStopMessage := false
	for _, message := range messages {
		if len(message) < protocol.HandshakeHeaderLen {
			continue
		}

		if protocol.HandshakeType(message[0]) == stopType {
			foundStopMessage = true
			break
		}

		transcript = append(transcript, message...)
	}

	if !foundStopMessage {
		return nil, fmt.Errorf("tls: handshake message %s not found", stopType)
	}

	return transcript, nil
}

func DeriveTLS13SharedSecretAndServerHelloMessage(
	privateKey *ecdh.PrivateKey,
	plaintextRecords []record.TLSPlaintext,
) ([]byte, []byte, error) {
	serverHello, serverHelloMessage, err := ParseTLS13ServerHelloAndMessage(plaintextRecords)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := DeriveTLS13SharedSecretFromServerHello(privateKey, serverHello)
	if err != nil {
		return nil, nil, err
	}

	return sharedSecret, serverHelloMessage, nil
}

func DeriveTLS13ServerEncryptedHandshakeMessages(
	ciphertextRecords []record.TLSCiphertext,
	sharedSecret []byte,
	clientHelloPayload []byte,
	serverHelloMessage []byte,
) ([]byte, error) {
	return deriveServerEncryptedHandshakeMessages(
		ciphertextRecords,
		sharedSecret,
		clientHelloPayload,
		serverHelloMessage,
	)
}

func deriveServerEncryptedHandshakeMessages(
	ciphertextRecords []record.TLSCiphertext,
	sharedSecret []byte,
	clientHelloPayload []byte,
	serverHelloMessage []byte,
) ([]byte, error) {
	handshakeSecrets, err := key.DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret, clientHelloPayload, serverHelloMessage)
	if err != nil {
		return nil, err
	}

	_, _, _, _, decryptedServerHandshakeRecords, err := DecodeAndParseServerTLS13HandshakeMessagesWithChaCha20Poly1305(
		ciphertextRecords,
		handshakeSecrets.ServerHandshakeKey,
		handshakeSecrets.ServerHandshakeIV,
		0,
	)
	if err != nil {
		return nil, err
	}

	serverEncryptedHandshakeMessages, err := ConcatHandshakeMessages(decryptedServerHandshakeRecords)
	if err != nil {
		return nil, err
	}

	return serverEncryptedHandshakeMessages, nil
}

func BuildClientFinishedRecord(sessionKeys *key.TLS13ChaCha20ClientSessionKeys, seq uint64) (record.TLSCiphertext, error) {
	finishedHandshake, err := handshake.NewHandshake(&handshake.Finished{VerifyData: sessionKeys.ClientFinishedVerifyData})
	if err != nil {
		return record.TLSCiphertext{}, err
	}

	return EncryptTLS13Record(
		sessionKeys.ClientHandshakeKey,
		sessionKeys.ClientHandshakeIV,
		seq,
		protocol.Handshake,
		finishedHandshake.Marshal(),
	)
}

func BuildClientApplicationDataRecord(sessionKeys *key.TLS13ChaCha20ClientSessionKeys, seq uint64, applicationData []byte) (record.TLSCiphertext, error) {
	return EncryptTLS13Record(
		sessionKeys.ClientApplicationKey,
		sessionKeys.ClientApplicationIV,
		seq,
		protocol.ApplicationData,
		applicationData,
	)
}
