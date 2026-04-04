package invalid

/**
 * Invalid message structure.
 *
 * This represents a record with an invalid content type (0x00).
 * Invalid content types should not appear in valid TLS communication
 * and typically indicate a protocol error or malformed record.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
 */
type Invalid struct {
	// Raw payload for debugging purposes
	Payload []byte
}

// Unmarshal parses the binary representation of an Invalid message.
func (inv *Invalid) Unmarshal(data []byte) error {
	// Invalid messages are just stored as-is for error reporting
	inv.Payload = make([]byte, len(data))
	copy(inv.Payload, data)
	return nil
}

// Marshal returns the binary representation of an Invalid message.
func (inv *Invalid) Marshal() []byte {
	result := make([]byte, len(inv.Payload))
	copy(result, inv.Payload)
	return result
}
