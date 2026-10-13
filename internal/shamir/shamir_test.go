package shamir

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAllCombinations(t *testing.T) {
	for _, cfg := range [][2]int{{2, 2}, {2, 5}, {3, 5}, {4, 6}, {5, 5}, {8, 10}} {
		m, n := cfg[0], cfg[1]
		secret := make([]byte, 99)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		pieces, err := Split(secret, m, n)
		if err != nil {
			t.Fatal(err)
		}
		checks := 0
		var walk func(start int, chosen []Piece)
		walk = func(start int, chosen []Piece) {
			if len(chosen) == m {
				got, err := Combine(chosen)
				if err != nil || !bytes.Equal(got, secret) {
					t.Fatalf("%d/%d combination failed: %v", m, n, err)
				}
				checks++
				return
			}
			for i := start; i < n; i++ {
				walk(i+1, append(chosen, pieces[i]))
			}
		}
		walk(0, nil)
		if checks == 0 {
			t.Fatal("no checks")
		}
		// Independent polynomial evaluation also recovers surplus shares.
		got, err := At(pieces[:m], pieces[n-1].X)
		if err != nil || !bytes.Equal(got, pieces[n-1].Y) {
			t.Fatalf("evaluation failed: %v", err)
		}
	}
}

func TestKnownPolynomial(t *testing.T) {
	// f(x) = 0x53 + 0xca*x, in the specified finite field.
	shares, err := splitWithRand([]byte{0x53}, 2, 3, bytes.NewReader([]byte{0xca}))
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range shares {
		if s.Y[0] != []byte{0x99, 0xdc, 0x16}[i] {
			t.Fatal("not expected field point")
		}
	}
	out, err := Combine(shares[1:])
	if err != nil || out[0] != 0x53 {
		t.Fatalf("bad secret: %x, %v", out, err)
	}
}

func TestInvalid(t *testing.T) {
	if _, err := Split([]byte{1}, 1, 3); err == nil {
		t.Fatal("accepted 1-of-n")
	}
	if _, err := Split([]byte{1}, 3, 2); err == nil {
		t.Fatal("accepted m>n")
	}
	if _, err := Combine([]Piece{{1, []byte{1}}, {1, []byte{2}}}); err == nil {
		t.Fatal("accepted duplicate")
	}
	if _, err := Combine([]Piece{{1, []byte{1}}, {2, []byte{2, 3}}}); err == nil {
		t.Fatal("accepted length mismatch")
	}
	if _, err := splitWithRand([]byte{1}, 2, 2, bytes.NewReader(nil)); err == nil {
		t.Fatal("accepted failed rng")
	}
}

func TestGF256(t *testing.T) {
	if mul(0x57, 0x83) != 0xc1 {
		t.Fatal("wrong GF(256) AES reference product")
	}
	for x := 1; x < 256; x++ {
		if mul(byte(x), inverse(byte(x))) != 1 {
			t.Fatalf("inverse failed: %d", x)
		}
	}
}

// Polynomial-long-multiplication reference, independent of mul's recurrence.
func TestFieldAgainstPolynomialReference(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			product := 0
			for bit := 0; bit < 8; bit++ {
				if b&(1<<bit) != 0 {
					product ^= a << bit
				}
			}
			for bit := 14; bit >= 8; bit-- {
				if product&(1<<bit) != 0 {
					product ^= 0x11b << (bit - 8)
				}
			}
			if mul(byte(a), byte(b)) != byte(product) {
				t.Fatalf("field mismatch: %d %d", a, b)
			}
		}
	}
}
func TestZeroCoefficientsAreAllowed(t *testing.T) {
	pieces, err := splitWithRand([]byte{0x42}, 3, 5, bytes.NewReader([]byte{0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Combine(pieces[:3])
	if err != nil || !bytes.Equal(out, []byte{0x42}) {
		t.Fatal("zero coefficient biased or rejected")
	}
}
