package key

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestGenerateX25519KeyPairAndSharedKey(t *testing.T) {
	clientPrivate, clientPublic, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair(client) failed: %v", err)
	}

	serverPrivate, serverPublic, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair(server) failed: %v", err)
	}

	clientShared, err := ComputeSharedKey(clientPrivate, serverPublic.Bytes())
	if err != nil {
		t.Fatalf("ComputeSharedKey(client) failed: %v", err)
	}

	serverShared, err := ComputeSharedKey(serverPrivate, clientPublic.Bytes())
	if err != nil {
		t.Fatalf("ComputeSharedKey(server) failed: %v", err)
	}

	if !bytes.Equal(clientShared, serverShared) {
		t.Fatal("shared keys must match")
	}
}

func TestPublicKeyHexRoundTrip(t *testing.T) {
	_, publicKey, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair() failed: %v", err)
	}

	hexValue, err := PublicKeyHex(publicKey)
	if err != nil {
		t.Fatalf("PublicKeyHex() failed: %v", err)
	}

	parsed, err := ParseX25519PublicKeyHex(hexValue)
	if err != nil {
		t.Fatalf("ParseX25519PublicKeyHex() failed: %v", err)
	}

	if !bytes.Equal(parsed.Bytes(), publicKey.Bytes()) {
		t.Fatal("parsed public key must match original")
	}
}

func TestDeriveTLS13ChaCha20HandshakeSecrets(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0x11}, X25519PublicKeyBytes)
	clientHello := bytes.Repeat([]byte{0x22}, 96)
	serverHello := bytes.Repeat([]byte{0x33}, 88)

	secrets, err := DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret, clientHello, serverHello)
	if err != nil {
		t.Fatalf("DeriveTLS13ChaCha20HandshakeSecrets() failed: %v", err)
	}

	if len(secrets.TranscriptHash) != TLS13HashLenSHA256 {
		t.Fatalf("len(TranscriptHash) = %d, want %d", len(secrets.TranscriptHash), TLS13HashLenSHA256)
	}
	if len(secrets.HandshakeSecret) != TLS13HashLenSHA256 {
		t.Fatalf("len(HandshakeSecret) = %d, want %d", len(secrets.HandshakeSecret), TLS13HashLenSHA256)
	}
	if len(secrets.ClientHandshakeKey) != chacha20poly1305.KeySize {
		t.Fatalf("len(ClientHandshakeKey) = %d, want %d", len(secrets.ClientHandshakeKey), chacha20poly1305.KeySize)
	}
	if len(secrets.ServerHandshakeKey) != chacha20poly1305.KeySize {
		t.Fatalf("len(ServerHandshakeKey) = %d, want %d", len(secrets.ServerHandshakeKey), chacha20poly1305.KeySize)
	}
	if len(secrets.ClientHandshakeIV) != chacha20poly1305.NonceSize {
		t.Fatalf("len(ClientHandshakeIV) = %d, want %d", len(secrets.ClientHandshakeIV), chacha20poly1305.NonceSize)
	}
	if len(secrets.ServerHandshakeIV) != chacha20poly1305.NonceSize {
		t.Fatalf("len(ServerHandshakeIV) = %d, want %d", len(secrets.ServerHandshakeIV), chacha20poly1305.NonceSize)
	}

	if bytes.Equal(secrets.ClientHandshakeKey, secrets.ServerHandshakeKey) {
		t.Fatal("client/server handshake keys should not match")
	}
	if bytes.Equal(secrets.ClientHandshakeIV, secrets.ServerHandshakeIV) {
		t.Fatal("client/server handshake IVs should not match")
	}
}

func TestDeriveTLS13ChaCha20ServerHandshakeKeyIV(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0x44}, X25519PublicKeyBytes)
	clientHello := bytes.Repeat([]byte{0x55}, 80)
	serverHello := bytes.Repeat([]byte{0x66}, 72)

	serverKey, serverIV, err := DeriveTLS13ChaCha20ServerHandshakeKeyIV(sharedSecret, clientHello, serverHello)
	if err != nil {
		t.Fatalf("DeriveTLS13ChaCha20ServerHandshakeKeyIV() failed: %v", err)
	}

	if len(serverKey) != chacha20poly1305.KeySize {
		t.Fatalf("len(serverKey) = %d, want %d", len(serverKey), chacha20poly1305.KeySize)
	}
	if len(serverIV) != chacha20poly1305.NonceSize {
		t.Fatalf("len(serverIV) = %d, want %d", len(serverIV), chacha20poly1305.NonceSize)
	}
}

func TestDeriveTLS13ChaCha20HandshakeSecretsErrors(t *testing.T) {
	_, err := DeriveTLS13ChaCha20HandshakeSecrets(nil, []byte{0x01}, []byte{0x02})
	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
}

func TestDeriveTLS13ChaCha20ClientSessionKeys(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0x10}, X25519PublicKeyBytes)
	clientHello := bytes.Repeat([]byte{0x20}, 64)
	serverHello := bytes.Repeat([]byte{0x30}, 64)
	serverEncryptedHandshakeMessages := bytes.Repeat([]byte{0x40}, 128)

	sessionKeys, err := DeriveTLS13ChaCha20ClientSessionKeys(sharedSecret, clientHello, serverHello, serverEncryptedHandshakeMessages)
	if err != nil {
		t.Fatalf("DeriveTLS13ChaCha20ClientSessionKeys() failed: %v", err)
	}

	if len(sessionKeys.ClientFinishedVerifyData) != TLS13HashLenSHA256 {
		t.Fatalf("len(ClientFinishedVerifyData) = %d, want %d", len(sessionKeys.ClientFinishedVerifyData), TLS13HashLenSHA256)
	}
	if len(sessionKeys.ClientApplicationKey) != chacha20poly1305.KeySize {
		t.Fatalf("len(ClientApplicationKey) = %d, want %d", len(sessionKeys.ClientApplicationKey), chacha20poly1305.KeySize)
	}
	if len(sessionKeys.ServerApplicationKey) != chacha20poly1305.KeySize {
		t.Fatalf("len(ServerApplicationKey) = %d, want %d", len(sessionKeys.ServerApplicationKey), chacha20poly1305.KeySize)
	}
	if len(sessionKeys.ClientApplicationIV) != chacha20poly1305.NonceSize {
		t.Fatalf("len(ClientApplicationIV) = %d, want %d", len(sessionKeys.ClientApplicationIV), chacha20poly1305.NonceSize)
	}
	if len(sessionKeys.ServerApplicationIV) != chacha20poly1305.NonceSize {
		t.Fatalf("len(ServerApplicationIV) = %d, want %d", len(sessionKeys.ServerApplicationIV), chacha20poly1305.NonceSize)
	}

	if bytes.Equal(sessionKeys.ClientApplicationKey, sessionKeys.ServerApplicationKey) {
		t.Fatal("client/server application keys should not match")
	}
}
