package share

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIndependentV1Vectors(t *testing.T) {
	data, err := os.ReadFile("testdata/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Entropy, Passphrase string
		Threshold, Total    int
		Tokens              []string
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		entropy, err := hex.DecodeString(v.Entropy)
		if err != nil {
			t.Fatal(err)
		}
		expected := Backup{Entropy: entropy, Passphrase: v.Passphrase, IncludesPassphrase: v.Passphrase != ""}
		ss := make([]Share, len(v.Tokens))
		for i, token := range v.Tokens {
			ss[i], err = Parse(token)
			if err != nil {
				t.Fatal(err)
			}
			if mustToken(t, ss[i]) != token {
				t.Fatal("independent canonical token mismatch")
			}
		}
		if err := VerifyAll(ss, ss); err != nil {
			t.Fatal(err)
		}
		for a := 0; a < len(ss); a++ {
			for b := a + 1; b < len(ss); b++ {
				for c := b + 1; c < len(ss); c++ {
					if err := VerifyBackup(expected, []Share{ss[a], ss[b], ss[c]}); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}
