// Package backup handles English BIP-39 mnemonic to/from raw entropy.
// The 13th/25th "word" is actually an independent optional BIP-39 passphrase.
package backup

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	bip39 "github.com/cosmos/go-bip39"
)

var indexes = func() map[string]int {
	m := make(map[string]int, len(bip39.EnglishWordList))
	for i, word := range bip39.EnglishWordList {
		m[word] = i
	}
	return m
}()

// Decode accepts only English BIP-39 with 12 or 24 words and validates its checksum.
// It returns the 128/256-bit ORIGINAL entropy, not the derived wallet seed.
func Decode(sentence string) ([]byte, error) {
	words := strings.Fields(sentence)
	if len(words) != 12 && len(words) != 24 {
		return nil, fmt.Errorf("expected exactly 12 or 24 BIP-39 words, got %d", len(words))
	}
	bits := len(words) * 11
	bitstream := make([]byte, (bits+7)/8)
	defer clear(bitstream)
	for i, word := range words {
		index, ok := indexes[word]
		if !ok {
			return nil, fmt.Errorf("word %d is not in the English BIP-39 list", i+1)
		}
		for b := 0; b < 11; b++ {
			if index&(1<<(10-b)) != 0 {
				offset := i*11 + b
				bitstream[offset/8] |= 1 << (7 - (offset % 8))
			}
		}
	}
	entropyLen := len(words) * 4 / 3 // 12 -> 16, 24 -> 32
	entropy := append([]byte(nil), bitstream[:entropyLen]...)
	checksum := sha256.Sum256(entropy)
	for b := 0; b < entropyLen/4; b++ { // 4 or 8 checksum bits
		encodedBit := bit(bitstream, entropyLen*8+b)
		expectedBit := bit(checksum[:], b)
		if encodedBit != expectedBit {
			clear(entropy)
			return nil, errors.New("BIP-39 checksum mismatch (possible mistyped word/order)")
		}
	}
	return entropy, nil
}

func bit(b []byte, offset int) byte { return (b[offset/8] >> (7 - offset%8)) & 1 }

func Encode(entropy []byte) (string, error) {
	if len(entropy) != 16 && len(entropy) != 32 {
		return "", errors.New("expected 16 or 32 bytes of raw entropy")
	}
	return bip39.NewMnemonic(entropy)
}
