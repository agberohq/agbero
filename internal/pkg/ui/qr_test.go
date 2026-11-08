package ui

import (
	"strings"
	"testing"
)

func TestQRTerminalANSIHasNoImageProtocol(t *testing.T) {
	q, err := NewQr("otpauth://totp/Agbero:admin?secret=JBSWY3DPEHPK3PXP&issuer=Agbero", QRLevelM)
	if err != nil {
		t.Fatal(err)
	}
	r := q.Result(4)
	if r.ANSI == "" || !strings.Contains(r.ANSI, "\x1b[30;47m") {
		t.Fatal("ANSI QR missing colors")
	}
	if strings.Contains(r.ANSI, "\x1b[?") || strings.Contains(r.ANSI, "\x1b_G") {
		t.Fatal("ANSI QR contains a terminal-image protocol query")
	}
}

func TestQRImageDetection(t *testing.T) {
	t.Setenv("AGBERO_QR", "ansi")
	if qrImageSupported() {
		t.Fatal("AGBERO_QR=ansi must disable image QR")
	}
	t.Setenv("AGBERO_QR", "image")
	if !qrImageSupported() {
		t.Fatal("AGBERO_QR=image must enable image QR")
	}
	t.Setenv("AGBERO_QR", "")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("TERM_PROGRAM", "")
	t.Setenv("KITTY_WINDOW_ID", "")
	t.Setenv("WEZTERM_PANE", "")
	if qrImageSupported() {
		t.Fatal("plain xterm must use ANSI QR")
	}
	t.Setenv("TERM", "xterm-kitty")
	if !qrImageSupported() {
		t.Fatal("kitty must use image QR")
	}
}

func TestQRPNGIsOpaqueBlackAndWhite(t *testing.T) {
	q, err := NewQr("otpauth://totp/Agbero:admin?secret=JBSWY3DPEHPK3PXP&issuer=Agbero", QRLevelM)
	if err != nil {
		t.Fatal(err)
	}
	img, err := DecodePNG(q.Result(4).PNG)
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	seenBlack, seenWhite := false, false
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			if a != 0xffff {
				t.Fatalf("transparent pixel at %d,%d", x, y)
			}
			if r == 0 && g == 0 && bl == 0 {
				seenBlack = true
			}
			if r == 0xffff && g == 0xffff && bl == 0xffff {
				seenWhite = true
			}
		}
	}
	if !seenBlack || !seenWhite {
		t.Fatalf("PNG is not black/white: black=%v white=%v", seenBlack, seenWhite)
	}
}
