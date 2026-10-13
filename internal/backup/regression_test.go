package backup

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestOfficialEnglishVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/english-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors [][2]string
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 16 {
		t.Fatal("missing official vectors")
	}
	for _, v := range vectors {
		want, _ := hex.DecodeString(v[0])
		got, err := Decode(v[1])
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("official decode: %v", err)
		}
		text, err := Encode(want)
		if err != nil || text != v[1] {
			t.Fatalf("official encode: %v", err)
		}
	}
}
func TestInvalidWordDoesNotLeak(t *testing.T) {
	secretTypo := "sensitive-mistyped-word"
	_, err := Decode(strings.Repeat("abandon ", 11) + secretTypo)
	if err == nil || strings.Contains(err.Error(), secretTypo) {
		t.Fatal("error reveals hidden mnemonic input")
	}
}
func TestMnemonicValidation(t *testing.T) {
	text := "\t" + strings.Repeat("abandon\u3000", 11) + "about\n"
	if _, err := Decode(text); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"", strings.Repeat("abandon ", 15), strings.Repeat("abandon ", 18), strings.Repeat("abandon ", 21), strings.Repeat("abandon ", 11) + "About", strings.Repeat("abandon ", 12)} {
		if _, err := Decode(text); err == nil {
			t.Fatal("invalid mnemonic accepted")
		}
	}
}
