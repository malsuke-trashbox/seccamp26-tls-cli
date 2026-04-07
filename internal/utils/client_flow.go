package utils

import (
	"crypto/ecdh"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/key"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/messages/record/handshake"
	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
)

func DeriveTLS13SharedSecretAndServerHelloMessage(
	privateKey *ecdh.PrivateKey,
	plaintextRecords []record.TLSPlaintext,
) ([]byte, []byte, error) {
	return deriveSharedSecretAndServerHelloMessage(privateKey, plaintextRecords)
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

func deriveSharedSecretAndServerHelloMessage(
	privateKey *ecdh.PrivateKey,
	plaintextRecords []record.TLSPlaintext,
) ([]byte, []byte, error) {
	serverHello, err := ParseServerHelloFromRecords(plaintextRecords)
	if err != nil {
		return nil, nil, err
	}

	serverShare, err := serverHello.ServerShare()
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := key.ComputeSharedKey(privateKey, serverShare.Data)
	if err != nil {
		return nil, nil, err
	}

	messages, err := CollectHandshakeMessages(plaintextRecords)
	if err != nil {
		return nil, nil, err
	}

	serverHelloMessage, ok := FindFirstHandshakeMessage(messages, protocol.TypeServerHello)
	if !ok {
		return nil, nil, ErrServerHelloNotFound
	}

	return sharedSecret, serverHelloMessage, nil
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

	decryptedServerHandshakeRecords, err := DecodeTLSCiphertextRecordsWithChaCha20Poly1305(
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
