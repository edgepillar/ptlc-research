package compatibility

import (
	"encoding/json"
	"strconv"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestRustFixedRecipientCompletionsMatchPinnedCoreVerifier(t *testing.T) {
	var terms map[string]json.RawMessage
	read(t, "../fixtures/nom_terms_v1.json", &terms)
	var fixture struct {
		Schema         string            `json:"schema"`
		Pair           map[string]string `json:"pair"`
		LongMessage    string            `json:"long_message_hex"`
		ShortMessage   string            `json:"short_message_hex"`
		LongSignature  string            `json:"long_signature_hex"`
		ShortSignature string            `json:"short_signature_hex"`
	}
	read(t, "../fixtures/nom_completions_v1.json", &fixture)
	text := func(key string) string {
		var result string
		if err := json.Unmarshal(terms[key], &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if text("profile") != profile || text("core_commit") != core || fixture.Schema != "ptlc-nom-public-completions-v1" {
		t.Fatal("profile changed")
	}
	for _, name := range []string{"long", "short"} {
		var leg map[string]string
		if err := json.Unmarshal(terms[name], &leg); err != nil {
			t.Fatal(err)
		}
		// Independent expected context, including the fixed counterparty destination.
		c := context{profile, text("chain_id"), 1, leg["entry_id_hex"], text(leg["recipient"] + "_address_hex")}
		chain, err := strconv.ParseUint(c.Chain, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		pre := []byte(profile)
		for shift := 56; shift >= 0; shift -= 8 {
			pre = append(pre, byte(chain>>shift))
		}
		pre = append(pre, raw(t, contract)...)
		pre = append(pre, 1)
		pre = append(pre, raw(t, c.Entry)...)
		pre = append(pre, raw(t, c.Destination)...)
		digest := sha3.Sum256(pre)
		message, signature := fixture.LongMessage, fixture.LongSignature
		if name == "short" {
			message, signature = fixture.ShortMessage, fixture.ShortSignature
		}
		if string(digest[:]) != string(raw(t, message)) || !verifies(1, raw(t, leg["funder_key_xonly_hex"]), digest[:], raw(t, signature)) {
			t.Fatal("Rust completion rejected by target Go resolution")
		}
		old := sha3.Sum256(raw(t, c.Entry+c.Destination))
		if verifies(1, raw(t, leg["funder_key_xonly_hex"]), old[:], raw(t, signature)) {
			t.Fatal("legacy replay accepted")
		}
		other := fixture.ShortSignature
		if name == "short" {
			other = fixture.LongSignature
		}
		if verifies(1, raw(t, leg["funder_key_xonly_hex"]), digest[:], raw(t, other)) {
			t.Fatal("cross-leg replay accepted")
		}
	}
}
