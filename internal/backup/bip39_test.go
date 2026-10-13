package backup

import (
	"bytes"
	"strings"
	"testing"
)

func TestBIP39KnownVectors(t *testing.T) {
	for _, tc := range []struct {
		mnemonic string
		size     int
	}{
		{"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", 16},
		{strings.TrimSpace(strings.Repeat("abandon ", 23)) + " art", 32},
	} {
		entropy, err := Decode(tc.mnemonic)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(entropy, make([]byte, tc.size)) {
			t.Fatalf("expected zero entropy, got %x", entropy)
		}
		got, err := Encode(entropy)
		if err != nil || got != tc.mnemonic {
			t.Fatalf("mnemonic mismatch %q: %v", got, err)
		}
		words := strings.Fields(tc.mnemonic)
		words[len(words)-1] = "zoo"
		if _, err := Decode(strings.Join(words, " ")); err == nil {
			t.Fatal("bad checksum accepted")
		}
	}
}
