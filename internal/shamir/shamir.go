// Package shamir implements byte-oriented Shamir secret sharing in GF(2^8).
// This is an independently implemented primitive; see the project security notice.
package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Piece is a point (X, Y) on an independent random polynomial per secret byte.
// X must be in [1,255].
type Piece struct {
	X byte
	Y []byte
}

// Split returns n shares such that any m distinct shares reconstruct secret.
// All polynomial coefficients come from a cryptographic random source.
func Split(secret []byte, m, n int) ([]Piece, error) {
	return splitWithRand(secret, m, n, rand.Reader)
}

// splitWithRand allows deterministic randomness to be injected in tests only.
func splitWithRand(secret []byte, m, n int, r io.Reader) ([]Piece, error) {
	if m < 2 || n < m || n > 255 {
		return nil, errors.New("require 2 <= threshold <= share count <= 255")
	}
	if len(secret) == 0 || len(secret) > 4096 {
		return nil, errors.New("secret size must be 1..4096 bytes")
	}
	if r == nil {
		return nil, errors.New("nil randomness source")
	}
	output := make([]Piece, n)
	for i := range output {
		output[i] = Piece{X: byte(i + 1), Y: make([]byte, len(secret))}
	}
	coefficients := make([]byte, m-1)
	defer clear(coefficients)
	for j, value := range secret {
		if _, err := io.ReadFull(r, coefficients); err != nil {
			for i := range output {
				clear(output[i].Y)
			}
			return nil, fmt.Errorf("CSPRNG failed: %w", err)
		}
		for i := range output {
			x := output[i].X
			// Horner evaluation, constant term is value.
			y := coefficients[len(coefficients)-1]
			for k := len(coefficients) - 2; k >= 0; k-- {
				y = mul(y, x) ^ coefficients[k]
			}
			output[i].Y[j] = mul(y, x) ^ value
		}
	}
	return output, nil
}

// At computes the polynomial value at x from a set of shares.
// At(..., 0) returns the original secret.
func At(pieces []Piece, x byte) ([]byte, error) {
	if len(pieces) < 2 || len(pieces) > 255 {
		return nil, errors.New("need 2..255 distinct shares")
	}
	nBytes := len(pieces[0].Y)
	if nBytes == 0 || nBytes > 4096 {
		return nil, errors.New("invalid share data length")
	}
	used := map[byte]bool{}
	for _, p := range pieces {
		if p.X == 0 || used[p.X] || len(p.Y) != nBytes {
			return nil, errors.New("duplicate, zero-indexed, or different-size shares")
		}
		used[p.X] = true
	}
	// Lagrange interpolation at x in characteristic-2 field, where -=+.
	output := make([]byte, nBytes)
	for i, p := range pieces {
		weight := byte(1)
		for j, q := range pieces {
			if i == j {
				continue
			}
			denominator := p.X ^ q.X
			weight = mul(weight, mul(x^q.X, inverse(denominator)))
		}
		for k, v := range p.Y {
			output[k] ^= mul(weight, v)
		}
	}
	return output, nil
}

func Combine(pieces []Piece) ([]byte, error) { return At(pieces, 0) }

// GF(256), AES's irreducible polynomial x^8+x^4+x^3+x+1.
func mul(a, b byte) byte {
	var out byte
	for j := 0; j < 8; j++ {
		out ^= a & (byte(0) - (b & 1))
		carry := a >> 7
		a = (a << 1) ^ (0x1b & (byte(0) - carry))
		b >>= 1
	}
	return out
}

func inverse(v byte) byte { // caller never supplies zero
	if v == 0 {
		panic("inverse(0)")
	}
	result := byte(1)
	// Fermat: inverse of a nonzero element = a^(256-2).
	for exponent := 254; exponent > 0; exponent >>= 1 {
		if exponent&1 != 0 {
			result = mul(result, v)
		}
		v = mul(v, v)
	}
	return result
}
