// Package share's English-word presentation is a reversible encoding of the
// EXISTING B39SSS1 wrapper. It is NOT a BIP-39 wallet mnemonic or SLIP-39.
package share

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "errors"
    "fmt"
    "strings"

    bip39 "github.com/cosmos/go-bip39"
)

const (
    WordPrefix = "B39WORDS1:"
    // Count and byte bounds apply before any allocation or word lookup.
    maxWrapperBytes = 28 + MaxPayloadBytes + sha256.Size
    maxWordCount = (maxWrapperBytes*8 + 10) / 11
    // Allow up to 11 characters per dictionary word and one delimiter.
    MaxWordTokenBytes = len(WordPrefix) + maxWordCount*12 + 2
    MaxShareInputBytes = MaxWordTokenBytes
)

var englishWordIndex = func() map[string]int {
    m := make(map[string]int, len(bip39.EnglishWordList))
    for i, word := range bip39.EnglishWordList {
        m[word] = i
    }
    return m
}()

// Words converts an existing share into English word notation. Each word
// encodes 11 bits of the ORIGINAL checksummed B39SSS1 binary wrapper,
// including its complete metadata and checksum. Extra final bits are zero.
// The result is losslessly interchangeable with s.Token().
func (s Share) Words() (string, error) {
    token, err := s.Token()
    if err != nil {
        return "", err
    }
    raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, Prefix))
    if err != nil {
        return "", err
    }
    defer clear(raw)
    count := (len(raw)*8 + 10) / 11
    words := make([]string, 0, count+1)
    words = append(words, WordPrefix)
    for i := 0; i < count; i++ {
        var value int
        for j := 0; j < 11; j++ {
            bit := i*11 + j
            value <<= 1
            if bit < len(raw)*8 {
                value |= int((raw[bit/8] >> uint(7-bit%8)) & 1)
            }
        }
        words = append(words, bip39.EnglishWordList[value])
    }
    return strings.Join(words, " "), nil
}

// ParseInput accepts both the original machine token and word notation.
// Word notation can be split across lines (e.g. on paper or in an export).
func ParseInput(input string) (Share, error) {
    input = strings.TrimSpace(input)
    if strings.HasPrefix(input, WordPrefix) {
        return ParseWords(input)
    }
    return Parse(input)
}

// ParseWords verifies canonical bit padding and count, then delegates to
// Parse() for full wrapper checksum, length, and field validation.
func ParseWords(input string) (Share, error) {
    var zero Share
    if len(input) > MaxWordTokenBytes {
        return zero, errors.New("word share too long")
    }
    fields := strings.Fields(input)
    if len(fields) < 2 || fields[0] != WordPrefix {
        return zero, errors.New("expected B39WORDS1: followed by English share words")
    }
    count := len(fields)-1
    if count > maxWordCount {
        return zero, errors.New("too many share words")
    }
    // The exact wrapper length is encoded in the original binary header.
    // Word count and zero padding must be canonical to avoid aliases.
    bits := count * 11
    stream := make([]byte, (bits+7)/8)
    defer clear(stream)
    for i, word := range fields[1:] {
        index, okay := englishWordIndex[word]
        if !okay {
            return zero, fmt.Errorf("share word %d is not in the English BIP-39 list", i+1)
        }
        for j := 0; j < 11; j++ {
            if index&(1<<uint(10-j)) != 0 {
                bit := i*11 + j
                stream[bit/8] |= 1 << uint(7-bit%8)
            }
        }
    }
    if len(stream) < 28 {
        return zero, errors.New("truncated word share header")
    }
    payloadLen := int(binary.BigEndian.Uint16(stream[26:28]))
    if payloadLen < MinPayloadBytes || payloadLen > MaxPayloadBytes {
        return zero, errors.New("invalid word share payload length")
    }
    rawLen := 28 + payloadLen + sha256.Size
    if count != (rawLen*8+10)/11 {
        return zero, errors.New("noncanonical word count for this share")
    }
    if rawLen > len(stream) {
        return zero, errors.New("truncated word share")
    }
    // The words encode ceil(rawBits/11)*11 bits. All unused bits MUST be zero.
    for bit := rawLen*8; bit < bits; bit++ {
        if stream[bit/8] & (1<<uint(7-bit%8)) != 0 {
            return zero, errors.New("nonzero trailing word padding")
        }
    }
    return Parse(Prefix + base64.RawURLEncoding.EncodeToString(stream[:rawLen]))
}
