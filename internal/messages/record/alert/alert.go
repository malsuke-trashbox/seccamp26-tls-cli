package alert

import (
	"errors"

	"github.com/malsuke/seccamp2026-tls13-cli/internal/protocol"
	"golang.org/x/crypto/cryptobyte"
)

/**
 * Alert message structure.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-6
 *
 * struct {
 *     AlertLevel level;
 *     AlertDescription description;
 * } Alert;
 */
type Alert struct {
	Level       protocol.AlertLevel
	Description protocol.AlertDescription
}

// Unmarshal parses the binary representation of an Alert message.
func (a *Alert) Unmarshal(data []byte) error {
	s := cryptobyte.String(data)

	var level uint8
	var description uint8

	if !s.ReadUint8(&level) {
		return errors.New("failed to read Alert level")
	}
	if !s.ReadUint8(&description) {
		return errors.New("failed to read Alert description")
	}

	if !s.Empty() {
		return errors.New("Alert has trailing bytes")
	}

	a.Level = protocol.AlertLevel(level)
	a.Description = protocol.AlertDescription(description)
	return nil
}

// Marshal returns the binary representation of an Alert message.
func (a *Alert) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(uint8(a.Level))
	b.AddUint8(uint8(a.Description))
	result, _ := b.Bytes()
	return result
}

// NewWarningAlert creates a warning level Alert with the given description.
func NewWarningAlert(desc protocol.AlertDescription) *Alert {
	return &Alert{
		Level:       protocol.AlertLevelWarning,
		Description: desc,
	}
}

// NewFatalAlert creates a fatal level Alert with the given description.
func NewFatalAlert(desc protocol.AlertDescription) *Alert {
	return &Alert{
		Level:       protocol.AlertLevelFatal,
		Description: desc,
	}
}
