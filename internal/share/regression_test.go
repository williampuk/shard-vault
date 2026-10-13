package share

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifyRequiresCompleteSet(t *testing.T) {
	b := Backup{Entropy: make([]byte, 16)}
	shares, err := Generate(b, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer Clear(shares)
	if err := VerifyAll(shares[:2], shares[:2]); err == nil {
		t.Fatal("incomplete backup reported verified")
	}
	reordered := []Share{shares[2], shares[0], shares[1]}
	if err := VerifyAll(shares, reordered); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAll(shares, []Share{shares[0], shares[1], shares[1]}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := VerifyBackup(b, shares); err != nil {
		t.Fatal(err)
	}
	b.Entropy[0] = 1
	if err := VerifyBackup(b, shares); err == nil {
		t.Fatal("wrong original input accepted")
	}
}

func TestPassphraseBoundaries(t *testing.T) {
	for _, pass := range []string{"", " ", "  leading and trailing  ", "quote\"and\\slash", "é", "e\u0301", "制限🔐", strings.Repeat("x", 512), strings.Repeat("🔐", 128), "\x00\t\r\n"} {
		for _, size := range []int{16, 32} {
			b := Backup{Entropy: make([]byte, size), Passphrase: pass, IncludesPassphrase: pass != ""}
			s, err := Generate(b, 2, 3)
			if err != nil {
				t.Fatal(err)
			}
			token := mustToken(t, s[0])
			if len(token) > MaxTokenBytes {
				t.Fatal("token bound too small")
			}
			if _, err := Parse(token + "\r\n"); err != nil {
				t.Fatal(err)
			}
			if err := VerifyBackup(b, s); err != nil {
				t.Fatal(err)
			}
			Clear(s)
		}
	}
	for _, b := range []Backup{
		{Entropy: make([]byte, 15)}, {Entropy: make([]byte, 33)},
		{Entropy: make([]byte, 16), Passphrase: "\xff", IncludesPassphrase: true},
		{Entropy: make([]byte, 16), Passphrase: strings.Repeat("x", 513), IncludesPassphrase: true},
		{Entropy: make([]byte, 16), IncludesPassphrase: true},
		{Entropy: make([]byte, 16), Passphrase: "forgot inclusion"},
	} {
		if _, err := Generate(b, 2, 3); err == nil {
			t.Fatal("accepted invalid backup")
		}
	}
}

func TestStructuralRejection(t *testing.T) {
	ss, _ := Generate(Backup{Entropy: make([]byte, 16)}, 2, 3)
	token := mustToken(t, ss[0])
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, Prefix))
	for _, tc := range []struct {
		offset int
		value  byte
	}{{0, 'X'}, {7, 1}, {7, 4}, {8, 17}, {9, 0}, {9, 4}, {26, 0xff}} {
		bad := bytes.Clone(raw)
		bad[tc.offset] = tc.value
		hash := sha256.Sum256(bad[:len(bad)-32])
		copy(bad[len(bad)-32:], hash[:])
		if _, err := Parse(Prefix + base64.RawURLEncoding.EncodeToString(bad)); err == nil {
			t.Fatalf("accepted invalid offset %d", tc.offset)
		}
	}
	for _, s := range []string{token + "=", token[:20] + "\n" + token[20:], strings.Repeat(" ", MaxTokenBytes+3) + token, token[:len(token)-1]} {
		if _, err := Parse(s); err == nil {
			t.Fatal("accepted malformed token")
		}
	}
	for _, s := range []Share{{}, {Threshold: 2, Total: 2, Index: 1, Value: make([]byte, 1)}, {Threshold: 2, Total: 2, Index: 1, Value: make([]byte, 65536)}} {
		if _, err := s.Token(); err == nil {
			t.Fatal("encoded invalid structure")
		}
	}
	// Invalid payloads with a correctly recomputed checksum reach the inner
	// parser, rather than merely exercising SHA-256 rejection.
	payload, _ := pack(Backup{Entropy: make([]byte, 16)})
	for _, tc := range []struct {
		offset int
		value  byte
	}{{0, 'X'}, {7, 2}, {7, 1}, {8, 32}, {25, 2}, {26, 1}} {
		bad := bytes.Clone(payload)
		bad[tc.offset] = tc.value
		hash := sha256.Sum256(bad[:len(bad)-32])
		copy(bad[len(bad)-32:], hash[:])
		if _, err := unpack(bad); err == nil {
			t.Fatal("accepted malformed payload")
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("")
	f.Add("B39SSS1:invalid")
	s, _ := Generate(Backup{Entropy: make([]byte, 16)}, 2, 2)
	token, _ := s[0].Token()
	f.Add(token)
	f.Fuzz(func(t *testing.T, text string) {
		s, err := Parse(text)
		if err != nil {
			return
		}
		token, err := s.Token()
		if err != nil {
			t.Fatal(err)
		}
		again, err := Parse(token)
		if err != nil || again.ID != s.ID || again.Index != s.Index || !bytes.Equal(again.Value, s.Value) {
			t.Fatal("parser round trip")
		}
	})
}
func FuzzUnpack(f *testing.F) {
	f.Add([]byte{})
	raw, _ := pack(Backup{Entropy: make([]byte, 16)})
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxPayloadBytes {
			return
		}
		b, err := unpack(data)
		if err != nil {
			return
		}
		round, err := pack(b)
		if err != nil || !bytes.Equal(data, round) {
			t.Fatal("payload round trip")
		}
	})
}

func TestEverySupportedThreshold(t *testing.T) {
	b := Backup{Entropy: bytes.Repeat([]byte{0xa5}, 32)}
	for n := 2; n <= 16; n++ {
		for m := 2; m <= n; m++ {
			s, err := Generate(b, m, n)
			if err != nil {
				t.Fatal(err)
			}
			for start := 0; start < n; start++ {
				subset := make([]Share, m)
				for j := range subset {
					subset[j] = s[(start+n-j)%n]
				}
				if err := VerifyBackup(b, subset); err != nil {
					t.Fatalf("%d-of-%d: %v", m, n, err)
				}
			}
			if err := VerifyAll(s, s); err != nil {
				t.Fatal(err)
			}
			Clear(s)
		}
	}
}
func FuzzRecover(f *testing.F) {
	f.Add([]byte{2, 3, 1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 5 || len(data) > 2048 {
			return
		}
		var id [16]byte
		value := data[5:]
		_, _ = Recover([]Share{{ID: id, Threshold: data[0], Total: data[1], Index: data[2], Value: value}, {ID: id, Threshold: data[0], Total: data[1], Index: data[3], Value: value}, {ID: id, Threshold: data[0], Total: data[1], Index: data[4], Value: value}})
	})
}
