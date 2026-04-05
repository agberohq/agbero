package ui

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"

	"rsc.io/qr"
)

// Constants re-exported so callers can specify ECC level without importing rsc.io/qr.
const (
	QRLevelL = qr.L // ~7% redundancy
	QRLevelM = qr.M // ~15% redundancy (default)
	QRLevelH = qr.H // ~30% redundancy
)

// half-block characters for compact terminal rendering (fallback only)
const (
	hbWhiteWhite = "█"
	hbBlackBlack = " "
	hbWhiteBlack = "▀"
	hbBlackWhite = "▄"
)

const quietZone = 4

// QRResult holds all representations of a generated QR code.
type QRResult struct {
	// Terminal is compact UTF-8 half-block art — fallback if image protocols fail.
	Terminal string
	// SVG is a self-contained <svg> element (no DOCTYPE / namespace).
	SVG string
	// PNG is raw PNG bytes — pass directly to go-termimg for rendering.
	PNG []byte
}

// QR represents an encoded QR code ready for format generation.
type QR struct {
	code *qr.Code
}

// NewQr creates a new QR code from content and ECC level.
func NewQr(content string, level qr.Level) (*QR, error) {
	code, err := qr.Encode(content, level)
	if err != nil {
		return nil, err
	}
	return &QR{code: code}, nil
}

// Result generates all output formats. Scale controls PNG/SVG resolution.
// Typical scale values: 4-8 for terminal display, 10+ for print/export.
func (q *QR) Result(scale int) *QRResult {
	return &QRResult{
		Terminal: q.terminalHalfBlocks(),
		SVG:      q.svg(scale),
		PNG:      q.pngBytes(scale),
	}
}

// terminalHalfBlocks renders QR as compact UTF-8 half-block art.
// Kept as fallback for terminals without image protocol support.
func (q *QR) terminalHalfBlocks() string {
	size := q.code.Size
	total := size + quietZone*2
	var b strings.Builder

	// top quiet zone (even rows only — half-block pairs two rows per line)
	for row := 0; row < quietZone; row += 2 {
		b.WriteString(strings.Repeat(hbWhiteWhite, total) + "\n")
	}

	for row := -quietZone; row < size+quietZone; row += 2 {
		b.WriteString(strings.Repeat(hbWhiteWhite, quietZone)) // left quiet
		for col := 0; col < size; col++ {
			top := q.safeBlack(col, row)
			bot := q.safeBlack(col, row+1)
			switch {
			case !top && !bot:
				b.WriteString(hbWhiteWhite)
			case top && bot:
				b.WriteString(hbBlackBlack)
			case top && !bot:
				b.WriteString(hbWhiteBlack)
			default: // !top && bot
				b.WriteString(hbBlackWhite)
			}
		}
		b.WriteString(strings.Repeat(hbWhiteWhite, quietZone) + "\n") // right quiet
	}

	// bottom quiet zone
	for row := 0; row < quietZone; row += 2 {
		b.WriteString(strings.Repeat(hbWhiteWhite, total) + "\n")
	}
	return b.String()
}

// svg generates an SVG string representation at the given cell scale.
func (q *QR) svg(scale int) string {
	size := q.code.Size
	total := (size + quietZone*2) * scale

	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `)
	writeInt(&b, total)
	b.WriteString(` `)
	writeInt(&b, total)
	b.WriteString(`" shape-rendering="crispEdges">`)
	b.WriteString(`<rect width="`)
	writeInt(&b, total)
	b.WriteString(`" height="`)
	writeInt(&b, total)
	b.WriteString(`" fill="white"/>`)

	for row := 0; row < size; row++ {
		for col := 0; col < size; col++ {
			if q.code.Black(col, row) {
				x := (col + quietZone) * scale
				y := (row + quietZone) * scale
				b.WriteString(`<rect x="`)
				writeInt(&b, x)
				b.WriteString(`" y="`)
				writeInt(&b, y)
				b.WriteString(`" width="`)
				writeInt(&b, scale)
				b.WriteString(`" height="`)
				writeInt(&b, scale)
				b.WriteString(`" fill="black"/>`)
			}
		}
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// pngBytes generates raw PNG bytes at the given scale factor.
// Output is ready for go-termimg: termimg.New(png.Decode(...)) or termimg.Open(bytes.NewReader(...))
func (q *QR) pngBytes(scale int) []byte {
	size := q.code.Size
	total := (size + quietZone*2) * scale

	img := image.NewGray(image.Rect(0, 0, total, total))

	// Fill white background
	for y := 0; y < total; y++ {
		for x := 0; x < total; x++ {
			img.SetGray(x, y, color.Gray{Y: 255})
		}
	}

	// Draw black modules
	for row := 0; row < size; row++ {
		for col := 0; col < size; col++ {
			if q.code.Black(col, row) {
				px := (col + quietZone) * scale
				py := (row + quietZone) * scale
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						img.SetGray(px+dx, py+dy, color.Gray{Y: 0})
					}
				}
			}
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// safeBlack checks if a module is black, treating out-of-bounds as white.
// Critical fix: uses >= for bounds check (valid indices: 0 to Size-1).
func (q *QR) safeBlack(x, y int) bool {
	if x < 0 || y < 0 || x >= q.code.Size || y >= q.code.Size {
		return false
	}
	return q.code.Black(x, y)
}

// DecodePNG converts raw PNG bytes to image.Image for go-termimg rendering.
// Usage: img, _ := termimg.New(qr.DecodePNG(result.PNG))
func DecodePNG(data []byte) (image.Image, error) {
	return png.Decode(bytes.NewReader(data))
}

// Helper functions (non-exported, used internally)

func writeInt(b *strings.Builder, n int) {
	b.WriteString(itoa(n))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
