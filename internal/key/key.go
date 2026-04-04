package key

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	RandomBytes32Length  = 32
	X25519PublicKeyBytes = 32
	TLS13HashLenSHA256   = sha256.Size
)

var (
	ErrNilPrivateKey = errors.New("tls: private key is nil")
	ErrNilPublicKey  = errors.New("tls: public key is nil")

	ErrEmptySharedSecret      = errors.New("tls: shared secret is empty")
	ErrEmptyClientHello       = errors.New("tls: client hello is empty")
	ErrEmptyServerHello       = errors.New("tls: server hello is empty")
	ErrInvalidHKDFLabelLength = errors.New("tls: hkdf label is too long")
	ErrInvalidHKDFContextLen  = errors.New("tls: hkdf context is too long")
)

type TLS13ChaCha20HandshakeSecrets struct {
	TranscriptHash               []byte
	HandshakeSecret              []byte
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	ClientHandshakeKey           []byte
	ClientHandshakeIV            []byte
	ServerHandshakeKey           []byte
	ServerHandshakeIV            []byte
}

type TLS13ChaCha20ClientSessionKeys struct {
	TranscriptHashAfterServerFinished []byte
	ClientFinishedVerifyData          []byte
	ClientHandshakeKey                []byte
	ClientHandshakeIV                 []byte
	ServerHandshakeKey                []byte
	ServerHandshakeIV                 []byte
	ClientApplicationKey              []byte
	ClientApplicationIV               []byte
	ServerApplicationKey              []byte
	ServerApplicationIV               []byte
}

func GenerateRandom32Bytes() ([RandomBytes32Length]byte, error) {
	var random [RandomBytes32Length]byte
	if _, err := rand.Read(random[:]); err != nil {
		return random, fmt.Errorf("tls: failed to generate random bytes: %w", err)
	}
	return random, nil
}

func GenerateX25519KeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: failed to generate x25519 key pair: %w", err)
	}
	return privateKey, privateKey.PublicKey(), nil
}

func ParseX25519PublicKey(raw []byte) (*ecdh.PublicKey, error) {
	publicKey, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("tls: invalid x25519 public key: %w", err)
	}
	return publicKey, nil
}

func ParseX25519PublicKeyHex(publicKeyHex string) (*ecdh.PublicKey, error) {
	raw, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to decode public key hex: %w", err)
	}
	return ParseX25519PublicKey(raw)
}

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

	result := make([]byte, len(shared))
	copy(result, shared)
	return result, nil
}

func ComputeSharedKeyWithPublicKey(privateKey ecdh.PrivateKey, peerPublicKey ecdh.PublicKey) ([]byte, error) {
	shared, err := privateKey.ECDH(&peerPublicKey)
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

func PublicKeyHex(publicKey *ecdh.PublicKey) (string, error) {
	bytes, err := PublicKeyBytes(publicKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func SharedKeyHex(sharedKey []byte) string {
	return hex.EncodeToString(sharedKey)
}

func DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret []byte, clientHello []byte, serverHello []byte) (*TLS13ChaCha20HandshakeSecrets, error) {
	if len(sharedSecret) == 0 {
		return nil, ErrEmptySharedSecret
	}
	if len(clientHello) == 0 {
		return nil, ErrEmptyClientHello
	}
	if len(serverHello) == 0 {
		return nil, ErrEmptyServerHello
	}

	transcriptHash := sha256.Sum256(append(cloneBytes(clientHello), serverHello...))

	zero := make([]byte, TLS13HashLenSHA256)
	earlySecret := hkdfExtractSHA256(zero, zero)
	emptyHash := sha256.Sum256(nil)
	derivedSecret, err := hkdfExpandLabelSHA256(earlySecret, "derived", emptyHash[:], TLS13HashLenSHA256)
	if err != nil {
		return nil, err
	}

	handshakeSecret := hkdfExtractSHA256(derivedSecret, sharedSecret)
	clientTrafficSecret, err := hkdfExpandLabelSHA256(handshakeSecret, "c hs traffic", transcriptHash[:], TLS13HashLenSHA256)
	if err != nil {
		return nil, err
	}
	serverTrafficSecret, err := hkdfExpandLabelSHA256(handshakeSecret, "s hs traffic", transcriptHash[:], TLS13HashLenSHA256)
	if err != nil {
		return nil, err
	}

	clientKey, err := hkdfExpandLabelSHA256(clientTrafficSecret, "key", nil, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	clientIV, err := hkdfExpandLabelSHA256(clientTrafficSecret, "iv", nil, chacha20poly1305.NonceSize)
	if err != nil {
		return nil, err
	}
	serverKey, err := hkdfExpandLabelSHA256(serverTrafficSecret, "key", nil, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	serverIV, err := hkdfExpandLabelSHA256(serverTrafficSecret, "iv", nil, chacha20poly1305.NonceSize)
	if err != nil {
		return nil, err
	}

	return &TLS13ChaCha20HandshakeSecrets{
		TranscriptHash:               transcriptHash[:],
		HandshakeSecret:              handshakeSecret,
		ClientHandshakeTrafficSecret: clientTrafficSecret,
		ServerHandshakeTrafficSecret: serverTrafficSecret,
		ClientHandshakeKey:           clientKey,
		ClientHandshakeIV:            clientIV,
		ServerHandshakeKey:           serverKey,
		ServerHandshakeIV:            serverIV,
	}, nil
}

func DeriveTLS13ChaCha20ServerHandshakeKeyIV(sharedSecret []byte, clientHello []byte, serverHello []byte) ([]byte, []byte, error) {
	secrets, err := DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret, clientHello, serverHello)
	if err != nil {
		return nil, nil, err
	}

	return cloneBytes(secrets.ServerHandshakeKey), cloneBytes(secrets.ServerHandshakeIV), nil
}

func DeriveTLS13ChaCha20ClientSessionKeys(sharedSecret []byte, clientHello []byte, serverHello []byte, serverEncryptedHandshakeMessages []byte) (*TLS13ChaCha20ClientSessionKeys, error) {
	handshakeSecrets, err := DeriveTLS13ChaCha20HandshakeSecrets(sharedSecret, clientHello, serverHello)
	if err != nil {
		return nil, err
	}

	transcript := make([]byte, 0, len(clientHello)+len(serverHello)+len(serverEncryptedHandshakeMessages))
	transcript = append(transcript, clientHello...)
	transcript = append(transcript, serverHello...)
	transcript = append(transcript, serverEncryptedHandshakeMessages...)
	transcriptHashAfterServerFinished := sha256.Sum256(transcript)

	clientFinishedKey, err := hkdfExpandLabelSHA256(handshakeSecrets.ClientHandshakeTrafficSecret, "finished", nil, TLS13HashLenSHA256)
	if err != nil {
		return nil, err
	}

	verifyMAC := hmac.New(sha256.New, clientFinishedKey)
	_, _ = verifyMAC.Write(transcriptHashAfterServerFinished[:])
	clientFinishedVerifyData := verifyMAC.Sum(nil)

	emptyHash := sha256.Sum256(nil)
	derivedSecretFromHandshake, err := hkdfExpandLabelSHA256(handshakeSecrets.HandshakeSecret, "derived", emptyHash[:], TLS13HashLenSHA256)
	if err != nil {
		return nil, err
	}

	zero := make([]byte, TLS13HashLenSHA256)
	masterSecret := hkdfExtractSHA256(derivedSecretFromHandshake, zero)
	clientApplicationTrafficSecret, err := hkdfExpandLabelSHA256(masterSecret, "c ap traffic", transcriptHashAfterServerFinished[:], TLS13HashLenSHA256)
	if err != nil {
		return nil, err
	}
	serverApplicationTrafficSecret, err := hkdfExpandLabelSHA256(masterSecret, "s ap traffic", transcriptHashAfterServerFinished[:], TLS13HashLenSHA256)
	if err != nil {
		return nil, err
	}

	clientApplicationKey, err := hkdfExpandLabelSHA256(clientApplicationTrafficSecret, "key", nil, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	clientApplicationIV, err := hkdfExpandLabelSHA256(clientApplicationTrafficSecret, "iv", nil, chacha20poly1305.NonceSize)
	if err != nil {
		return nil, err
	}
	serverApplicationKey, err := hkdfExpandLabelSHA256(serverApplicationTrafficSecret, "key", nil, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	serverApplicationIV, err := hkdfExpandLabelSHA256(serverApplicationTrafficSecret, "iv", nil, chacha20poly1305.NonceSize)
	if err != nil {
		return nil, err
	}

	return &TLS13ChaCha20ClientSessionKeys{
		TranscriptHashAfterServerFinished: cloneBytes(transcriptHashAfterServerFinished[:]),
		ClientFinishedVerifyData:          cloneBytes(clientFinishedVerifyData),
		ClientHandshakeKey:                cloneBytes(handshakeSecrets.ClientHandshakeKey),
		ClientHandshakeIV:                 cloneBytes(handshakeSecrets.ClientHandshakeIV),
		ServerHandshakeKey:                cloneBytes(handshakeSecrets.ServerHandshakeKey),
		ServerHandshakeIV:                 cloneBytes(handshakeSecrets.ServerHandshakeIV),
		ClientApplicationKey:              cloneBytes(clientApplicationKey),
		ClientApplicationIV:               cloneBytes(clientApplicationIV),
		ServerApplicationKey:              cloneBytes(serverApplicationKey),
		ServerApplicationIV:               cloneBytes(serverApplicationIV),
	}, nil
}

func hkdfExtractSHA256(salt []byte, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, TLS13HashLenSHA256)
	}

	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpandLabelSHA256(secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	if len(fullLabel) > 255 {
		return nil, ErrInvalidHKDFLabelLength
	}
	if len(context) > 255 {
		return nil, ErrInvalidHKDFContextLen
	}

	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, []byte(fullLabel)...)
	info = append(info, byte(len(context)))
	info = append(info, context...)

	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out); err != nil {
		return nil, fmt.Errorf("tls: hkdf expand label %q failed: %w", label, err)
	}

	return out, nil
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
