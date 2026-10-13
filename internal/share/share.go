// Package share defines the B39SSS1 project-specific share format and
// wraps Shamir sharing of an integrity-checked BIP-39 backup payload.
// These shares are NOT SLIP-0039 compatible.
package share

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/williampuk/shard-vault/internal/shamir"
)

const (
	Prefix             = "B39SSS1:"
	shareMagic         = "B39SHR1"
	payloadMagic       = "B39PAY1"
	MaxPassphraseBytes = 512
	MinPayloadBytes    = 7 + 1 + 1 + 16 + 2 + sha256.Size
	MaxPayloadBytes    = 7 + 1 + 1 + 32 + 2 + MaxPassphraseBytes + sha256.Size
	MaxTokenBytes      = len(Prefix) + (28+MaxPayloadBytes+sha256.Size)*8/6 + 1
)

type Backup struct {
	Entropy            []byte // raw BIP-39 entropy, 16 or 32 bytes, NOT the derived BIP-39 seed
	Passphrase         string // optional BIP-39 passphrase, exact UTF-8 bytes, not normalized
	IncludesPassphrase bool
}

type Share struct {
	ID        [16]byte
	Threshold byte
	Total     byte
	Index     byte
	Value     []byte
}

func pack(b Backup) ([]byte, error) {
	if len(b.Entropy) != 16 && len(b.Entropy) != 32 {
		return nil, errors.New("entropy must be 16 or 32 bytes (12/24 BIP-39 words)")
	}
	if !utf8.ValidString(b.Passphrase) {
		return nil, errors.New("passphrase must be valid UTF-8")
	}
	if len(b.Passphrase) > MaxPassphraseBytes {
		return nil, errors.New("passphrase must be <= 512 UTF-8 bytes")
	}
	if !b.IncludesPassphrase && b.Passphrase != "" {
		return nil, errors.New("passphrase supplied but not selected for backup")
	}
	if b.IncludesPassphrase && b.Passphrase == "" {
		return nil, errors.New("empty passphrase should be excluded")
	}
	size := len(payloadMagic) + 1 + 1 + len(b.Entropy) + 2 + len(b.Passphrase)
	buf := make([]byte, size, size+sha256.Size)
	copy(buf, payloadMagic)
	if b.IncludesPassphrase {
		buf[len(payloadMagic)] = 1
	}
	buf[len(payloadMagic)+1] = byte(len(b.Entropy))
	at := len(payloadMagic) + 2
	copy(buf[at:], b.Entropy)
	at += len(b.Entropy)
	binary.BigEndian.PutUint16(buf[at:at+2], uint16(len(b.Passphrase)))
	at += 2
	copy(buf[at:], b.Passphrase)
	digest := sha256.Sum256(buf)
	buf = append(buf, digest[:]...)
	return buf, nil
}

func unpack(data []byte) (Backup, error) {
	var b Backup
	if len(data) < 7+1+1+16+2+sha256.Size || string(data[:len(payloadMagic)]) != payloadMagic {
		return b, errors.New("invalid backup payload marker or length")
	}
	headerLen := len(data) - sha256.Size
	checksum := sha256.Sum256(data[:headerLen])
	if subtle.ConstantTimeCompare(checksum[:], data[headerLen:]) != 1 {
		return b, errors.New("backup integrity check failed; wrong or corrupted shares")
	}
	flag, entropyLen := data[7], int(data[8])
	if (flag != 0 && flag != 1) || (entropyLen != 16 && entropyLen != 32) {
		return b, errors.New("invalid backup payload parameters")
	}
	at := 9 + entropyLen
	if at+2 > headerLen {
		return b, errors.New("truncated payload")
	}
	passLen := int(binary.BigEndian.Uint16(data[at : at+2]))
	at += 2
	if passLen > MaxPassphraseBytes || at+passLen != headerLen {
		return b, errors.New("invalid passphrase length")
	}
	if (flag == 0 && passLen != 0) || (flag == 1 && passLen == 0) {
		return b, errors.New("inconsistent passphrase flag")
	}
	if !utf8.Valid(data[at:headerLen]) {
		return Backup{}, errors.New("recovered passphrase is not valid UTF-8")
	}
	b.Entropy = append([]byte(nil), data[9:9+entropyLen]...)
	b.IncludesPassphrase = flag == 1
	b.Passphrase = string(data[at:headerLen])
	return b, nil
}

// Generate makes 2..16 shares, requiring threshold >= 2.
func Generate(b Backup, threshold, total int) ([]Share, error) {
	if threshold < 2 || threshold > total || total > 16 {
		return nil, errors.New("require 2 <= threshold <= total <= 16")
	}
	payload, err := pack(b)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return nil, fmt.Errorf("cannot generate backup ID: %w", err)
	}
	points, err := shamir.Split(payload, threshold, total)
	if err != nil {
		return nil, err
	}
	result := make([]Share, total)
	for i, p := range points {
		result[i] = Share{ID: id, Threshold: byte(threshold), Total: byte(total), Index: p.X, Value: p.Y}
	}
	return result, nil
}

// Token encodes a versioned, self-describing share with an unkeyed checksum
// for typos/corruption. The secret payload has its own INTERNAL checksum.
func (s Share) Token() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	raw := make([]byte, 7+3+16+2+len(s.Value)+sha256.Size)
	defer clear(raw)
	copy(raw, shareMagic)
	raw[7], raw[8], raw[9] = s.Threshold, s.Total, s.Index
	copy(raw[10:26], s.ID[:])
	binary.BigEndian.PutUint16(raw[26:28], uint16(len(s.Value)))
	copy(raw[28:], s.Value)
	checksum := sha256.Sum256(raw[:len(raw)-sha256.Size])
	copy(raw[len(raw)-sha256.Size:], checksum[:])
	return Prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func Parse(token string) (Share, error) {
	var s Share
	if len(token) > MaxTokenBytes+2 {
		return s, errors.New("share too long")
	}
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, Prefix) {
		return s, errors.New("not a B39SSS1 share")
	}
	if strings.ContainsAny(token, "\r\n") {
		return s, errors.New("share must be one complete line")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, Prefix))
	defer clear(raw)
	if err != nil {
		return s, fmt.Errorf("invalid base64 share: %w", err)
	}
	if len(raw) < 28+sha256.Size+1 || string(raw[:7]) != shareMagic {
		return s, errors.New("invalid share header")
	}
	ySize := int(binary.BigEndian.Uint16(raw[26:28]))
	if ySize < MinPayloadBytes || ySize > MaxPayloadBytes || len(raw) != 28+ySize+sha256.Size {
		return s, errors.New("invalid share length")
	}
	sum := sha256.Sum256(raw[:len(raw)-sha256.Size])
	if subtle.ConstantTimeCompare(sum[:], raw[len(raw)-sha256.Size:]) != 1 {
		return s, errors.New("share checksum mismatch")
	}
	s.Threshold, s.Total, s.Index = raw[7], raw[8], raw[9]
	if s.Threshold < 2 || s.Threshold > s.Total || s.Total > 16 || s.Index == 0 || s.Index > s.Total {
		return Share{}, errors.New("invalid share threshold, total, or index")
	}
	copy(s.ID[:], raw[10:26])
	s.Value = append([]byte(nil), raw[28:28+ySize]...)
	return s, nil
}

func Recover(shares []Share) (Backup, error) {
	var empty Backup
	if len(shares) == 0 {
		return empty, errors.New("no shares")
	}
	first := shares[0]
	if first.Threshold < 2 || first.Threshold > first.Total || first.Total > 16 {
		return empty, errors.New("invalid threshold")
	}
	if len(shares) < int(first.Threshold) {
		return empty, fmt.Errorf("need at least %d shares", first.Threshold)
	}
	if len(shares) > int(first.Total) {
		return empty, errors.New("too many shares")
	}
	used := map[byte]bool{}
	points := make([]shamir.Piece, len(shares))
	for i, s := range shares {
		if s.ID != first.ID || s.Threshold != first.Threshold || s.Total != first.Total ||
			s.Index < 1 || s.Index > s.Total || len(s.Value) != len(first.Value) || used[s.Index] {
			return empty, errors.New("mixed backup sets, inconsistent share, or repeated index")
		}
		if err := s.Validate(); err != nil {
			return empty, err
		}
		used[s.Index] = true
		points[i] = shamir.Piece{X: s.Index, Y: s.Value}
	}
	necessary := points[:int(first.Threshold)]
	// If extra shares are present, check that each lies on the SAME polynomial.
	for _, extra := range points[int(first.Threshold):] {
		expected, err := shamir.At(necessary, extra.X)
		if err != nil {
			return empty, err
		}
		okay := subtle.ConstantTimeCompare(expected, extra.Y)
		clear(expected)
		if okay != 1 {
			return empty, errors.New("inconsistent extra share")
		}
	}
	payload, err := shamir.Combine(necessary)
	if err != nil {
		return empty, err
	}
	defer clear(payload)
	return unpack(payload)
}

// Validate rejects invalid programmatically constructed shares as well as tokens.
func (s Share) Validate() error {
	if s.Threshold < 2 || s.Threshold > s.Total || s.Total > 16 || s.Index < 1 || s.Index > s.Total {
		return errors.New("invalid share threshold, total, or index")
	}
	if len(s.Value) < MinPayloadBytes || len(s.Value) > MaxPayloadBytes {
		return errors.New("invalid share payload length")
	}
	return nil
}

// Clear best-effort clears mutable share values; it cannot erase string copies.
func Clear(shares []Share) {
	for i := range shares {
		clear(shares[i].Value)
	}
}

// VerifyAll requires the complete declared set, not merely a recoverable subset.
// It checks exact equality in any order and consistency of every Shamir point.
func VerifyAll(expected, received []Share) error {
	if len(expected) == 0 || len(expected) != len(received) || len(expected) != int(expected[0].Total) {
		return errors.New("all n shares must be supplied")
	}
	byIndex := make(map[byte]Share, len(expected))
	for _, s := range expected {
		if err := s.Validate(); err != nil {
			return err
		}
		if _, exists := byIndex[s.Index]; exists {
			return errors.New("duplicate expected share")
		}
		byIndex[s.Index] = s
	}
	seen := map[byte]bool{}
	for _, got := range received {
		original, found := byIndex[got.Index]
		if !found || seen[got.Index] || got.ID != original.ID || got.Threshold != original.Threshold || got.Total != original.Total || subtle.ConstantTimeCompare(got.Value, original.Value) != 1 {
			return fmt.Errorf("share %d did not match original backup", got.Index)
		}
		seen[got.Index] = true
	}
	b, err := Recover(received)
	if err != nil {
		return fmt.Errorf("reconstruction failed: %w", err)
	}
	defer clear(b.Entropy)
	return nil
}

// VerifyBackup compares recovery against the original user input, rather than
// comparing two reconstructions of the same generated shares.
func VerifyBackup(expected Backup, shares []Share) error {
	got, err := Recover(shares)
	if err != nil {
		return err
	}
	defer clear(got.Entropy)
	if subtle.ConstantTimeCompare(got.Entropy, expected.Entropy) != 1 ||
		subtle.ConstantTimeCompare([]byte(got.Passphrase), []byte(expected.Passphrase)) != 1 ||
		got.IncludesPassphrase != expected.IncludesPassphrase {
		return errors.New("recovered backup differs from original input")
	}
	return nil
}
