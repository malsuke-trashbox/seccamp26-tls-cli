package utils

import (
	"crypto/ecdh"
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

var ErrServerFinishedNotFound = errors.New("tls: server finished not found in records")

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
