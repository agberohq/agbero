package security

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

// GF256 provides Galois Field 2^8 arithmetic operations.
// Uses AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
type GF256 struct {
	// Pre-computed log/exp tables for fast multiplication
	logTable [256]uint16
	expTable [256]uint8
}

// NewGF256 creates a new GF(2^8) instance with pre-computed tables.
func NewGF256() *GF256 {
	gf := &GF256{}
	gf.initTables()
	return gf
}

// initTables pre-computes log and exp tables for fast operations.
func (gf *GF256) initTables() {
	const generator uint8 = 0x03 // Generator for AES field
	var x uint8 = 1
	for i := 0; i < 255; i++ {
		gf.expTable[i] = x
		gf.logTable[x] = uint16(i)
		x = gf.mulPoly(x, generator)
	}
	// expTable wraps around: 2^255 = 1
	gf.expTable[255] = gf.expTable[0]
}

// mulPoly multiplies two polynomials in GF(2^8).
func (gf *GF256) mulPoly(a, b uint8) uint8 {
	var result uint8 = 0
	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			result ^= a
		}
		hiBit := (a & 0x80) != 0
		a <<= 1
		if hiBit {
			a ^= 0x1B // AES polynomial without x^8 term
		}
		b >>= 1
	}
	return result
}

// Add returns a + b in GF(2^8) (XOR).
func (gf *GF256) Add(a, b uint8) uint8 {
	return a ^ b
}

// Sub returns a - b in GF(2^8) (same as Add).
func (gf *GF256) Sub(a, b uint8) uint8 {
	return a ^ b
}

// Mul returns a * b in GF(2^8) using log tables.
func (gf *GF256) Mul(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}

	// Constant-time-ish: compute both paths
	logA := gf.logTable[a]
	logB := gf.logTable[b]
	sum := (int(logA) + int(logB)) % 255
	result := gf.expTable[sum]

	// Ensure zero if either input is zero (constant time)
	var zero uint8
	maskA := subtle.ConstantTimeByteEq(a, 0)
	maskB := subtle.ConstantTimeByteEq(b, 0)
	mask := maskA | maskB

	if mask == 1 {
		return zero
	}
	return result
}

// Div returns a / b in GF(2^8).
func (gf *GF256) Div(a, b uint8) uint8 {
	if b == 0 {
		panic("divide by zero")
	}
	if a == 0 {
		return 0
	}

	logA := gf.logTable[a]
	logB := gf.logTable[b]
	diff := (int(logA) - int(logB)) % 255
	if diff < 0 {
		diff += 255
	}
	return gf.expTable[diff]
}

// Inv returns the multiplicative inverse of a in GF(2^8).
func (gf *GF256) Inv(a uint8) uint8 {
	if a == 0 {
		return 0
	}
	return gf.expTable[255-gf.logTable[a]]
}

// Polynomial represents a polynomial over GF(2^8).
type Polynomial struct {
	gf           *GF256
	coefficients []uint8 // coefficients[0] is the constant term (intercept)
}

// NewPolynomial creates a random polynomial with given intercept and degree.
// The highest coefficient is guaranteed to be non-zero to ensure exact degree.
func (gf *GF256) NewPolynomial(intercept uint8, degree uint8) (*Polynomial, error) {
	if degree == 0 {
		return nil, errors.New("degree must be at least 1")
	}
	p := &Polynomial{
		gf:           gf,
		coefficients: make([]uint8, degree+1),
	}
	p.coefficients[0] = intercept

	if _, err := rand.Read(p.coefficients[1:]); err != nil {
		return nil, err
	}

	// Ensure highest coefficient is non-zero to maintain exact degree
	// This is critical for Shamir's Secret Sharing security
	for p.coefficients[degree] == 0 {
		if _, err := rand.Read(p.coefficients[degree:]); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// Evaluate returns p(x) using Horner's method.
func (p *Polynomial) Evaluate(x uint8) uint8 {
	if x == 0 {
		return p.coefficients[0]
	}

	degree := len(p.coefficients) - 1
	result := p.coefficients[degree]

	for i := degree - 1; i >= 0; i-- {
		result = p.gf.Add(p.gf.Mul(result, x), p.coefficients[i])
	}
	return result
}

// Shamir provides Shamir's Secret Sharing operations.
type Shamir struct {
	gf *GF256
}

// NewShamir creates a new Shamir instance.
func NewShamir() *Shamir {
	return &Shamir{
		gf: NewGF256(),
	}
}

// Share represents a single share with x coordinate and y values.
type Share struct {
	X uint8
	Y []uint8
}

// Split divides secret into n shares, requiring k to reconstruct.
func (s *Shamir) Split(secret []byte, parts, threshold int) ([]*Share, error) {
	if parts < threshold {
		return nil, errors.New("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, errors.New("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, errors.New("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, errors.New("cannot split empty secret")
	}

	// Generate unique x coordinates (1..255)
	xCoords, err := s.generateXCoords(parts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate x coordinates: %w", err)
	}

	// Create shares
	shares := make([]*Share, parts)
	for i := 0; i < parts; i++ {
		shares[i] = &Share{
			X: xCoords[i],
			Y: make([]uint8, len(secret)),
		}
	}

	// For each byte of secret, create a polynomial and evaluate at each x
	for byteIdx, byteVal := range secret {
		poly, err := s.gf.NewPolynomial(byteVal, uint8(threshold-1))
		if err != nil {
			return nil, fmt.Errorf("failed to create polynomial: %w", err)
		}

		for i, x := range xCoords {
			shares[i].Y[byteIdx] = poly.Evaluate(x)
		}
	}

	return shares, nil
}

// generateXCoords generates n unique random x coordinates in range 1..255.
func (s *Shamir) generateXCoords(n int) ([]uint8, error) {
	if n > 255 {
		return nil, errors.New("too many parts")
	}

	// Fisher-Yates shuffle of 1..255
	coords := make([]uint8, 255)
	for i := range coords {
		coords[i] = uint8(i + 1)
	}

	for i := 254; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		j := int(jBig.Int64())
		coords[i], coords[j] = coords[j], coords[i]
	}

	return coords[:n], nil
}

// Combine reconstructs secret from shares using Lagrange interpolation.
func (s *Shamir) Combine(shares []*Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("need at least 2 shares")
	}

	// Verify all shares have same length
	yLen := len(shares[0].Y)
	for i, sh := range shares {
		if len(sh.Y) != yLen {
			return nil, fmt.Errorf("share %d has wrong length", i)
		}
	}

	// Check for duplicate x coordinates
	xMap := make(map[uint8]bool)
	for _, sh := range shares {
		if xMap[sh.X] {
			return nil, errors.New("duplicate x coordinate detected")
		}
		xMap[sh.X] = true
	}

	// Reconstruct each byte
	secret := make([]uint8, yLen)

	for byteIdx := 0; byteIdx < yLen; byteIdx++ {
		// Build points for this byte position
		xSamples := make([]uint8, len(shares))
		ySamples := make([]uint8, len(shares))

		for i, sh := range shares {
			xSamples[i] = sh.X
			ySamples[i] = sh.Y[byteIdx]
		}

		secret[byteIdx] = s.interpolate(xSamples, ySamples, 0)
	}

	return secret, nil
}

// interpolate computes f(x) using Lagrange interpolation.
func (s *Shamir) interpolate(xSamples, ySamples []uint8, x uint8) uint8 {
	n := len(xSamples)
	var result uint8 = 0

	for i := 0; i < n; i++ {
		// Compute Lagrange basis polynomial l_i(x)
		basis := uint8(1)

		for j := 0; j < n; j++ {
			if i == j {
				continue
			}

			// l_i(x) = prod_{j!=i} (x - x_j) / (x_i - x_j)
			numerator := s.gf.Sub(x, xSamples[j])
			denominator := s.gf.Sub(xSamples[i], xSamples[j])
			term := s.gf.Div(numerator, denominator)
			basis = s.gf.Mul(basis, term)
		}

		// Add y_i * l_i(x) to result
		group := s.gf.Mul(ySamples[i], basis)
		result = s.gf.Add(result, group)
	}

	return result
}

// SerializeShare converts a share to bytes for storage.
func (s *Shamir) SerializeShare(sh *Share) []byte {
	// Format: [1 byte x][y values...]
	result := make([]byte, 1+len(sh.Y))
	result[0] = sh.X
	copy(result[1:], sh.Y)
	return result
}

// DeserializeShare converts bytes back to a share.
func (s *Shamir) DeserializeShare(data []byte) (*Share, error) {
	if len(data) < 2 {
		return nil, errors.New("share data too short")
	}
	// Copy Y data so secureZero on input doesn't corrupt the share
	yCopy := make([]byte, len(data)-1)
	copy(yCopy, data[1:])
	return &Share{
		X: data[0],
		Y: yCopy,
	}, nil
}
