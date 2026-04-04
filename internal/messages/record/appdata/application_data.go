package appdata

/**
 * ApplicationData message structure.
 *
 * ApplicationData messages are the actual encrypted payloads sent over TLS.
 * The actual content of application data is opaque to the TLS protocol.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
 *
 * struct {
 *     opaque data<0..2^16-1>;
 * } ApplicationData;
 */
type ApplicationData struct {
	Data []byte
}

// Unmarshal parses the binary representation of ApplicationData.
func (a *ApplicationData) Unmarshal(data []byte) error {
	// ApplicationData is just raw bytes
	a.Data = make([]byte, len(data))
	copy(a.Data, data)
	return nil
}

// Marshal returns the binary representation of ApplicationData.
func (a *ApplicationData) Marshal() []byte {
	result := make([]byte, len(a.Data))
	copy(result, a.Data)
	return result
}
