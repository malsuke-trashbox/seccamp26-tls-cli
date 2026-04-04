package protocol

import "fmt"

type ContentType uint8

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
 */
const (
	Invalid          ContentType = 0x00
	ChangeCipherSpec ContentType = 0x14
	Alert            ContentType = 0x15
	Handshake        ContentType = 0x16
	ApplicationData  ContentType = 0x17
)

type TLSVersion uint16

const (
	TLS_VERSION_1_0 TLSVersion = 0x0301
	TLS_VERSION_1_1 TLSVersion = 0x0302
	TLS_VERSION_1_2 TLSVersion = 0x0303
	TLS_VERSION_1_3 TLSVersion = 0x0304
)

func (v TLSVersion) String() string {
	switch v {
	case TLS_VERSION_1_0:
		return "TLS 1.0"
	case TLS_VERSION_1_1:
		return "TLS 1.1"
	case TLS_VERSION_1_2:
		return "TLS 1.2"
	case TLS_VERSION_1_3:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown TLS version: 0x%04x", uint16(v))
	}
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4
 */
type HandshakeType uint8

const (
	TypeClientHello         HandshakeType = 1
	TypeServerHello         HandshakeType = 2
	TypeNewSessionTicket    HandshakeType = 4
	TypeEncryptedExtensions HandshakeType = 8
	TypeCertificate         HandshakeType = 11
	TypeCertificateRequest  HandshakeType = 13
	TypeCertificateVerify   HandshakeType = 15
	TypeFinished            HandshakeType = 20
	TypeKeyUpdate           HandshakeType = 24
	TypeMessageHash         HandshakeType = 254
)

func (ht HandshakeType) String() string {
	switch ht {
	case TypeClientHello:
		return "ClientHello"
	case TypeServerHello:
		return "ServerHello"
	case TypeNewSessionTicket:
		return "NewSessionTicket"
	case TypeEncryptedExtensions:
		return "EncryptedExtensions"
	case TypeCertificate:
		return "Certificate"
	case TypeCertificateRequest:
		return "CertificateRequest"
	case TypeCertificateVerify:
		return "CertificateVerify"
	case TypeFinished:
		return "Finished"
	case TypeKeyUpdate:
		return "KeyUpdate"
	case TypeMessageHash:
		return "MessageHash"
	default:
		return fmt.Sprintf("Unknown HandshakeType: 0x%02x", uint8(ht))
	}
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
 */
type CipherSuite uint16

const (
	TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384       CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 CipherSuite = 0x1303
	TLS_AES_128_CCM_SHA256       CipherSuite = 0x1304
	TLS_AES_128_CCM_8_SHA256     CipherSuite = 0x1305
)

func (cs CipherSuite) String() string {
	switch cs {
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case TLS_AES_128_CCM_SHA256:
		return "TLS_AES_128_CCM_SHA256"
	case TLS_AES_128_CCM_8_SHA256:
		return "TLS_AES_128_CCM_8_SHA256"
	default:
		return fmt.Sprintf("Unknown CipherSuite: 0x%04x", uint16(cs))
	}
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
 */
type ExtensionType uint16

const (
	ExtServerName              ExtensionType = 0
	ExtSupportedCurves         ExtensionType = 10
	ExtSignatureAlgorithms     ExtensionType = 13
	ExtExtendedMasterSecret    ExtensionType = 23
	ExtSupportedVersions       ExtensionType = 43
	ExtCookie                  ExtensionType = 44
	ExtCertificateAuthorities  ExtensionType = 47
	ExtSignatureAlgorithmsCert ExtensionType = 50
	ExtKeyShare                ExtensionType = 51
	ExtPSKKeyExchangeModes     ExtensionType = 45
	ExtRenegotiationInfo       ExtensionType = 0xff01
	ExtEncryptedClientHello    ExtensionType = 0xfe0d
)

func (et ExtensionType) String() string {
	switch et {
	case ExtServerName:
		return "ServerName"
	case ExtSupportedCurves:
		return "SupportedGroups"
	case ExtSignatureAlgorithms:
		return "SignatureAlgorithms"
	case ExtKeyShare:
		return "KeyShare"
	case ExtSupportedVersions:
		return "SupportedVersions"
	case ExtPSKKeyExchangeModes:
		return "PSKKeyExchangeModes"
	case ExtCookie:
		return "Cookie"
	case ExtCertificateAuthorities:
		return "CertificateAuthorities"
	case ExtSignatureAlgorithmsCert:
		return "SignatureAlgorithmsCert"
	case ExtEncryptedClientHello:
		return "EncryptedClientHello"
	case ExtExtendedMasterSecret:
		return "ExtendedMasterSecret"
	case ExtRenegotiationInfo:
		return "RenegotiationInfo"
	default:
		return fmt.Sprintf("Unknown ExtensionType: 0x%04x", uint16(et))
	}
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
 */
type CurveID uint16

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
	X25519    CurveID = 29
)

func (c CurveID) String() string {
	switch c {
	case CurveP256:
		return "P-256"
	case CurveP384:
		return "P-384"
	case CurveP521:
		return "P-521"
	case X25519:
		return "X25519"
	default:
		return fmt.Sprintf("Unknown CurveID: 0x%04x", uint16(c))
	}
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
 */
type SignatureScheme uint16

const (
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	Ed25519 SignatureScheme = 0x0807
)

func (ss SignatureScheme) String() string {
	switch ss {
	case PKCS1WithSHA256:
		return "PKCS1WithSHA256"
	case PKCS1WithSHA384:
		return "PKCS1WithSHA384"
	case PKCS1WithSHA512:
		return "PKCS1WithSHA512"
	case PSSWithSHA256:
		return "PSSWithSHA256"
	case PSSWithSHA384:
		return "PSSWithSHA384"
	case PSSWithSHA512:
		return "PSSWithSHA512"
	case ECDSAWithP256AndSHA256:
		return "ECDSAWithP256AndSHA256"
	case ECDSAWithP384AndSHA384:
		return "ECDSAWithP384AndSHA384"
	case ECDSAWithP521AndSHA512:
		return "ECDSAWithP521AndSHA512"
	case Ed25519:
		return "Ed25519"
	default:
		return fmt.Sprintf("Unknown SignatureScheme: 0x%04x", uint16(ss))
	}
}

const HandshakeHeaderLen = 4

const RecordHeaderLen = 5

const MaxPayloadLen = 16384

const MaxCiphertextLen = MaxPayloadLen + 256

const InitialRecordVersion = TLS_VERSION_1_0

const MaxVersionForFirstRecord TLSVersion = 0x1000

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-6
 */
type AlertLevel uint8

const (
	AlertLevelWarning = AlertLevel(1)
	AlertLevelFatal   = AlertLevel(2)
)

type AlertDescription uint8

const (
	AlertCloseNotify            = AlertDescription(0)
	AlertUnexpectedMessage      = AlertDescription(10)
	AlertBadRecordMAC           = AlertDescription(20)
	AlertDecryptionFailed       = AlertDescription(21)
	AlertRecordOverflow         = AlertDescription(22)
	AlertDecompressionFailure   = AlertDescription(30)
	AlertHandshakeFailure       = AlertDescription(40)
	AlertNoCertificate          = AlertDescription(41)
	AlertBadCertificate         = AlertDescription(42)
	AlertUnsupportedCertificate = AlertDescription(43)
	AlertCertificateRevoked     = AlertDescription(44)
	AlertCertificateExpired     = AlertDescription(45)
	AlertCertificateUnknown     = AlertDescription(46)
	AlertIllegalParameter       = AlertDescription(47)
	AlertUnknownCA              = AlertDescription(48)
	AlertAccessDenied           = AlertDescription(49)
	AlertDecodeError            = AlertDescription(50)
	AlertDecryptError           = AlertDescription(51)
	AlertExportRestriction      = AlertDescription(60)
	AlertProtocolVersion        = AlertDescription(70)
	AlertInsufficientSecurity   = AlertDescription(71)
	AlertInternalError          = AlertDescription(80)
	AlertInappropriateFallback  = AlertDescription(86)
	AlertUserCanceled           = AlertDescription(90)
	AlertNoRenegotiation        = AlertDescription(100)
	AlertMissingExtension       = AlertDescription(109)
	AlertUnsupportedExtension   = AlertDescription(110)
)

func (ad AlertDescription) String() string {
	switch ad {
	case AlertCloseNotify:
		return "close_notify"
	case AlertUnexpectedMessage:
		return "unexpected_message"
	case AlertBadRecordMAC:
		return "bad_record_mac"
	case AlertDecryptionFailed:
		return "decryption_failed"
	case AlertRecordOverflow:
		return "record_overflow"
	case AlertDecompressionFailure:
		return "decompression_failure"
	case AlertHandshakeFailure:
		return "handshake_failure"
	case AlertNoCertificate:
		return "no_certificate"
	case AlertBadCertificate:
		return "bad_certificate"
	case AlertUnsupportedCertificate:
		return "unsupported_certificate"
	case AlertCertificateRevoked:
		return "certificate_revoked"
	case AlertCertificateExpired:
		return "certificate_expired"
	case AlertCertificateUnknown:
		return "certificate_unknown"
	case AlertIllegalParameter:
		return "illegal_parameter"
	case AlertUnknownCA:
		return "unknown_ca"
	case AlertAccessDenied:
		return "access_denied"
	case AlertDecodeError:
		return "decode_error"
	case AlertDecryptError:
		return "decrypt_error"
	case AlertExportRestriction:
		return "export_restriction"
	case AlertProtocolVersion:
		return "protocol_version"
	case AlertInsufficientSecurity:
		return "insufficient_security"
	case AlertInternalError:
		return "internal_error"
	case AlertInappropriateFallback:
		return "inappropriate_fallback"
	case AlertUserCanceled:
		return "user_canceled"
	case AlertNoRenegotiation:
		return "no_renegotiation"
	case AlertMissingExtension:
		return "missing_extension"
	case AlertUnsupportedExtension:
		return "unsupported_extension"
	default:
		return fmt.Sprintf("Unknown AlertDescription: %d", uint8(ad))
	}
}
