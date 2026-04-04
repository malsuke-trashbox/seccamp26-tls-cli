package key

import (
	"bytes"
	"testing"
)

func TestGenerateRandom32Bytes(t *testing.T) {
	random, err := GenerateRandom32Bytes()
	if err != nil {
		t.Fatalf("GenerateRandom32Bytes() failed: %v", err)
	}
	if len(random) != RandomBytes32Length {
		t.Fatalf("len(random) = %d, want %d", len(random), RandomBytes32Length)
	}
}

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

	serverShared, err := ComputeSharedKeyWithPublicKey(serverPrivate, clientPublic)
	if err != nil {
		t.Fatalf("ComputeSharedKeyWithPublicKey(server) failed: %v", err)
	}

	if !bytes.Equal(clientShared, serverShared) {
		t.Fatal("client and server shared keys must match")
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

func TestComputeSharedKeyWithNilPrivateKey(t *testing.T) {
	_, err := ComputeSharedKey(nil, make([]byte, X25519PublicKeyBytes))
	if err == nil {
		t.Fatal("ComputeSharedKey() should fail with nil private key")
	}
}
