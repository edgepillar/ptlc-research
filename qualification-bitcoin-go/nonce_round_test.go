package qualification

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Only public fixture fields are loaded. The script engine is independent of
// the Rust aggregate signer and supplies no chain-state or finality evidence.
type nonceRoundVector struct {
	Leg                 string   `json:"leg"`
	RoundID             string   `json:"round_id_hex"`
	BindingDigest       string   `json:"binding_digest_hex"`
	RoundDigest         string   `json:"round_digest_hex"`
	PublicKey           string   `json:"public_key_hex"`
	Message             string   `json:"message_hex"`
	PublicNonces        []string `json:"public_nonces_hex"`
	NonceCommitments    []string `json:"nonce_commitments_hex"`
	PartialSignatures   []string `json:"partial_signatures_hex"`
	AdaptorPreSignature string   `json:"adaptor_presignature_hex"`
	Signature           string   `json:"signature_hex"`
	Valid               bool     `json:"valid"`
}

func bitcoinNonceRound(t *testing.T) nonceRoundVector {
	t.Helper()
	data, err := os.ReadFile("../qualification/fixtures/nonce_rounds.json")
	if err != nil {
		t.Fatal("public nonce fixture unavailable")
	}
	var corpus struct {
		Schema  string             `json:"schema"`
		Note    string             `json:"note"`
		Vectors []nonceRoundVector `json:"vectors"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal("invalid public nonce fixture schema")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("trailing nonce fixture data")
	}
	if corpus.Schema != "ptlc-public-nonce-round-fixture-v1" || len(corpus.Vectors) != 2 ||
		corpus.Vectors[0].Leg != "bitcoin" || corpus.Vectors[1].Leg != "zenon" {
		t.Fatal("unexpected nonce fixture schema, leg order, or count")
	}
	v := corpus.Vectors[0]
	if !v.Valid || !bytes.Equal(decode(t, v.RoundID, 32), bytes.Repeat([]byte{61}, 32)) {
		t.Fatal("unexpected Bitcoin round identity or expectation")
	}
	return v
}

func TestNonceRoundSignatureExecutesExactBitcoinClaim(t *testing.T) {
	f := fixture(t)
	v := bitcoinNonceRound(t)
	if !bytes.Equal(decode(t, v.PublicKey, 32), decode(t, f.Taproot.OutputKey, 32)) ||
		!bytes.Equal(decode(t, v.Message, 32), decode(t, f.Claim.Sighash, 32)) {
		t.Fatal("nonce-round signature does not target the qualified output key and claim message")
	}
	tx := transaction(t, f.Claim, f, false)
	beforeTxID, beforeWitnessID := tx.TxHash(), tx.WitnessHash()
	signature := decode(t, v.Signature, 64)
	if bytes.Equal(tx.TxIn[0].Witness[0], signature) {
		t.Fatal("new nonce round must produce a different fixture signature")
	}
	tx.TxIn[0].Witness = wire.TxWitness{signature}
	if len(tx.TxIn[0].Witness) != 1 || len(tx.TxIn[0].Witness[0]) != 64 {
		t.Fatal("claim must contain one DEFAULT signature and no annex")
	}
	if tx.TxHash() != beforeTxID || tx.WitnessHash() == beforeWitnessID {
		t.Fatal("signature substitution must preserve txid and change wtxid")
	}
	pkScript := decode(t, f.Funding.PkScript, 34)
	previous := txscript.NewCannedPrevOutputFetcher(pkScript, f.Funding.Value)
	hashes := txscript.NewTxSigHashes(tx, previous)
	message, err := txscript.CalcTaprootSignatureHash(hashes, txscript.SigHashDefault, tx, 0, previous)
	if err != nil || !bytes.Equal(message, decode(t, v.Message, 32)) {
		t.Fatal("independent transaction digest differs after witness substitution")
	}
	if err := execute(tx, pkScript, f.Funding.Value); err != nil {
		t.Fatalf("nonce-round completed signature failed Bitcoin script execution: %v", err)
	}
	for _, mutation := range []string{"signature", "output-value"} {
		t.Run(mutation, func(t *testing.T) {
			changed := tx.Copy()
			if mutation == "signature" {
				changed.TxIn[0].Witness[0][63] ^= 1
			} else {
				changed.TxOut[0].Value--
			}
			if err := execute(changed, pkScript, f.Funding.Value); err == nil {
				t.Fatal("mutated nonce-round claim unexpectedly passed script execution")
			}
		})
	}
}
