package key

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	RandomBytes32Length  = 32
	X25519PublicKeyBytes = 32
)

var (
	ErrNilPrivateKey = errors.New("tls: private key is nil")
	ErrNilPublicKey  = errors.New("tls: public key is nil")
)

// GenerateRandom32Bytes generates cryptographically secure 32-byte random data.
func GenerateRandom32Bytes() ([RandomBytes32Length]byte, error) {
	var random [RandomBytes32Length]byte
	if _, err := rand.Read(random[:]); err != nil {
		return random, fmt.Errorf("tls: failed to generate random bytes: %w", err)
	}
	return random, nil
}

// GenerateX25519KeyPair generates an X25519 key pair.
func GenerateX25519KeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: failed to generate x25519 key pair: %w", err)
	}
	return privateKey, privateKey.PublicKey(), nil
}

// ParseX25519PublicKey parses a raw peer public key as X25519.
func ParseX25519PublicKey(raw []byte) (*ecdh.PublicKey, error) {
	publicKey, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("tls: invalid x25519 public key: %w", err)
	}
	return publicKey, nil
}

// ParseX25519PublicKeyHex parses a hex-encoded peer public key as X25519.
func ParseX25519PublicKeyHex(publicKeyHex string) (*ecdh.PublicKey, error) {
	raw, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to decode public key hex: %w", err)
	}
	return ParseX25519PublicKey(raw)
}

// ComputeSharedKey computes the X25519 shared secret from a private key and peer raw public key.
func ComputeSharedKey(privateKey *ecdh.PrivateKey, peerPublicKey []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrNilPrivateKey
	}

	peer, err := ParseX25519PublicKey(peerPublicKey)
	if err != nil {
		return nil, err
	}

	shared, err := privateKey.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to compute shared key: %w", err)
	}
	return shared, nil
}

// ComputeSharedKeyWithPublicKey computes the X25519 shared secret from key objects.
func ComputeSharedKeyWithPublicKey(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrNilPrivateKey
	}
	if peerPublicKey == nil {
		return nil, ErrNilPublicKey
	}

	shared, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to compute shared key: %w", err)
	}
	return shared, nil
}

// PublicKeyBytes returns a copy of the public key bytes.
func PublicKeyBytes(publicKey *ecdh.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrNilPublicKey
	}
	bytes := publicKey.Bytes()
	copied := make([]byte, len(bytes))
	copy(copied, bytes)
	return copied, nil
}

// PublicKeyHex returns a hex-encoded public key.
func PublicKeyHex(publicKey *ecdh.PublicKey) (string, error) {
	bytes, err := PublicKeyBytes(publicKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SharedKeyHex returns a hex-encoded shared key.
func SharedKeyHex(sharedKey []byte) string {
	return hex.EncodeToString(sharedKey)
}
