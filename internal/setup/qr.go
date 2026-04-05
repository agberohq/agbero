package setup

import (
	"github.com/agberohq/agbero/internal/pkg/ui"
	"rsc.io/qr"
)

// TOTPProvisioningQR encodes a TOTP otpauth:// URI into a QR code using
// ECC level M (recommended for provisioning URIs).
func TOTPProvisioningQR(uri string) (*ui.QRResult, error) {
	// Cast ui.QRLevelM to qr.Level to prevent any strict type mismatch errors
	return GenerateQR(uri, qr.Level(ui.QRLevelM))
}

// GenerateQR encodes content at the given ECC level and returns all three forms.
// This is a convenience function for backward compatibility.
func GenerateQR(content string, level qr.Level) (*ui.QRResult, error) {
	qrCode, err := ui.NewQr(content, level)
	if err != nil {
		return nil, err
	}

	// Use the Result() method to get the populated *ui.QRResult
	// Passing 6 as the scale based on your original PNG(6) requirement.
	return qrCode.Result(6), nil
}
