package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Public synthetic transactions only. This package has no signing or RPC API.
type transactionVector struct {
	Raw                 string `json:"raw_tx_hex"`
	TxID                string `json:"txid_hex"`
	WitnessTxID         string `json:"wtxid_hex"`
	Sighash             string `json:"sighash_hex"`
	Version             int32  `json:"version"`
	Sequence            uint32 `json:"sequence"`
	LockTime            uint32 `json:"locktime"`
	OutputValue         int64  `json:"output_value_sats"`
	DestinationPkScript string `json:"destination_script_pubkey_hex"`
}

type transactionFixture struct {
	Schema  string `json:"schema"`
	Note    string `json:"note"`
	Funding struct {
		TxID     string `json:"txid_hex"`
		Vout     uint32 `json:"vout"`
		Value    int64  `json:"value_sats"`
		PkScript string `json:"script_pubkey_hex"`
	} `json:"funding"`
	Taproot struct {
		InternalKey    string `json:"internal_key_xonly_hex"`
		OutputKey      string `json:"output_key_xonly_hex"`
		MerkleRoot     string `json:"merkle_root_hex"`
		LeafHash       string `json:"tapleaf_hash_hex"`
		LeafVersion    byte   `json:"leaf_version"`
		RefundKey      string `json:"refund_key_xonly_hex"`
		RefundScript   string `json:"refund_leaf_script_hex"`
		ControlBlock   string `json:"control_block_hex"`
		RefundLockTime uint32 `json:"refund_locktime"`
	} `json:"taproot"`
	Claim  transactionVector `json:"claim"`
	Refund transactionVector `json:"refund"`
}

func decode(t *testing.T, text string, width int) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(data) != text || (width >= 0 && len(data) != width) {
		t.Fatal("fixture contains noncanonical hex or an unexpected field width")
	}
	return data
}

func fixture(t *testing.T) transactionFixture {
	t.Helper()
	data, err := os.ReadFile("../qualification/fixtures/bitcoin_transactions.json")
	if err != nil {
		t.Fatal("public Bitcoin transaction fixture unavailable")
	}
	var f transactionFixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		t.Fatal("invalid public Bitcoin transaction fixture schema")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("trailing fixture data")
	}
	if f.Schema != "ptlc-bitcoin-transactions-v1" || f.Funding.Value != 200000 || f.Taproot.RefundLockTime != 500000100 {
		t.Fatal("unexpected fixture identity, amount or refund policy")
	}
	return f
}

func parseTransaction(raw []byte) (*wire.MsgTx, error) {
	reader := bytes.NewReader(raw)
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(reader); err != nil {
		return nil, err
	}
	if reader.Len() != 0 {
		return nil, errors.New("trailing transaction data")
	}
	var encoded bytes.Buffer
	if err := tx.Serialize(&encoded); err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, encoded.Bytes()) {
		return nil, errors.New("noncanonical transaction serialization")
	}
	return tx, nil
}

func transaction(t *testing.T, v transactionVector, f transactionFixture, refund bool) *wire.MsgTx {
	t.Helper()
	tx, err := parseTransaction(decode(t, v.Raw, -1))
	if err != nil {
		t.Fatal("fixture transaction is not an exact canonical serialization")
	}
	if len(tx.TxIn) != 1 || len(tx.TxOut) != 1 || tx.Version != 2 || v.Version != 2 {
		t.Fatal("fixture must have version 2 and exactly one input and one output")
	}
	if tx.TxHash().String() != v.TxID || tx.WitnessHash().String() != v.WitnessTxID {
		t.Fatal("transaction identifier mismatch")
	}
	decode(t, v.TxID, 32)
	decode(t, v.WitnessTxID, 32)
	decode(t, f.Funding.TxID, 32)
	previous, err := chainhash.NewHashFromStr(f.Funding.TxID)
	if err != nil || tx.TxIn[0].PreviousOutPoint.Hash != *previous || tx.TxIn[0].PreviousOutPoint.Index != f.Funding.Vout {
		t.Fatal("transaction spends a different funding outpoint")
	}
	if len(tx.TxIn[0].SignatureScript) != 0 || tx.TxIn[0].Sequence != 0xfffffffd || v.Sequence != 0xfffffffd {
		t.Fatal("unexpected input script or sequence")
	}
	if tx.TxOut[0].Value != 199000 || v.OutputValue != 199000 || tx.TxOut[0].Value >= f.Funding.Value {
		t.Fatal("unexpected destination amount or fee")
	}
	destination := decode(t, v.DestinationPkScript, 34)
	if !txscript.IsPayToTaproot(destination) || !bytes.Equal(tx.TxOut[0].PkScript, destination) {
		t.Fatal("destination script mismatch")
	}
	expectedLockTime, witnessLength := uint32(0), 1
	if refund {
		expectedLockTime, witnessLength = f.Taproot.RefundLockTime, 3
	}
	if tx.LockTime != expectedLockTime || v.LockTime != expectedLockTime || len(tx.TxIn[0].Witness) != witnessLength {
		t.Fatal("unexpected locktime, witness count, or annex")
	}
	if len(tx.TxIn[0].Witness[0]) != 64 {
		t.Fatal("SIGHASH_DEFAULT requires the selected 64-byte signature encoding")
	}
	if refund && (!bytes.Equal(tx.TxIn[0].Witness[1], decode(t, f.Taproot.RefundScript, -1)) || !bytes.Equal(tx.TxIn[0].Witness[2], decode(t, f.Taproot.ControlBlock, 33))) {
		t.Fatal("refund witness does not reveal the exact agreed leaf and control block")
	}
	return tx
}

func execute(tx *wire.MsgTx, pkScript []byte, amount int64) error {
	previous := txscript.NewCannedPrevOutputFetcher(pkScript, amount)
	hashes := txscript.NewTxSigHashes(tx, previous)
	engine, err := txscript.NewEngine(pkScript, tx, 0, txscript.StandardVerifyFlags, nil, hashes, amount, previous)
	if err != nil {
		return err
	}
	return engine.Execute()
}

func TestExactFundingTreeAndTransactionSerialization(t *testing.T) {
	f := fixture(t)
	if f.Taproot.LeafVersion != 0xc0 || f.Taproot.RefundLockTime < txscript.LockTimeThreshold {
		t.Fatal("expected a base tapscript leaf with a timestamp CLTV policy")
	}
	refundKey := decode(t, f.Taproot.RefundKey, 32)
	if _, err := schnorr.ParsePubKey(refundKey); err != nil {
		t.Fatal("invalid refund public key")
	}
	script, err := txscript.NewScriptBuilder().AddInt64(int64(f.Taproot.RefundLockTime)).AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).AddOp(txscript.OP_DROP).AddData(refundKey).AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil || !bytes.Equal(script, decode(t, f.Taproot.RefundScript, -1)) {
		t.Fatal("refund leaf differs from the selected Alice-only CLTV script")
	}
	leaf := txscript.NewBaseTapLeaf(script)
	leafHash := leaf.TapHash()
	if !bytes.Equal(leafHash[:], decode(t, f.Taproot.LeafHash, 32)) || !bytes.Equal(leafHash[:], decode(t, f.Taproot.MerkleRoot, 32)) {
		t.Fatal("single-leaf Taproot root/hash mismatch")
	}
	internal, err := schnorr.ParsePubKey(decode(t, f.Taproot.InternalKey, 32))
	if err != nil {
		t.Fatal("invalid aggregate internal key")
	}
	output := txscript.ComputeTaprootOutputKey(internal, leafHash[:])
	if !bytes.Equal(schnorr.SerializePubKey(output), decode(t, f.Taproot.OutputKey, 32)) {
		t.Fatal("tweaked output key mismatch")
	}
	pkScript, err := txscript.PayToTaprootScript(output)
	if err != nil || !bytes.Equal(pkScript, decode(t, f.Funding.PkScript, 34)) {
		t.Fatal("funding script does not commit to the expected output key")
	}
	control, err := txscript.ParseControlBlock(decode(t, f.Taproot.ControlBlock, 33))
	if err != nil || control.LeafVersion != txscript.BaseLeafVersion || !control.InternalKey.IsEqual(internal) || !bytes.Equal(control.RootHash(script), leafHash[:]) {
		t.Fatal("control block does not describe the expected one-leaf tree")
	}
	if err := txscript.VerifyTaprootLeafCommitment(control, schnorr.SerializePubKey(output), script); err != nil {
		t.Fatal("refund leaf/control-block commitment rejected")
	}
	transaction(t, f.Claim, f, false)
	transaction(t, f.Refund, f, true)
}

func TestIndependentClaimAndRefundSighashes(t *testing.T) {
	f := fixture(t)
	pkScript := decode(t, f.Funding.PkScript, 34)
	for name, v := range map[string]transactionVector{"claim": f.Claim, "refund": f.Refund} {
		t.Run(name, func(t *testing.T) {
			tx := transaction(t, v, f, name == "refund")
			previous := txscript.NewCannedPrevOutputFetcher(pkScript, f.Funding.Value)
			hashes := txscript.NewTxSigHashes(tx, previous)
			var digest []byte
			var err error
			if name == "claim" {
				digest, err = txscript.CalcTaprootSignatureHash(hashes, txscript.SigHashDefault, tx, 0, previous)
			} else {
				leaf := txscript.NewBaseTapLeaf(decode(t, f.Taproot.RefundScript, -1))
				digest, err = txscript.CalcTapscriptSignaturehash(hashes, txscript.SigHashDefault, tx, 0, previous, leaf)
			}
			if err != nil || !bytes.Equal(digest, decode(t, v.Sighash, 32)) {
				t.Fatal("independently calculated BIP341/BIP342 sighash differs")
			}
		})
	}
}

func TestScriptEngineAcceptsBothSpendPaths(t *testing.T) {
	f := fixture(t)
	for name, v := range map[string]transactionVector{"claim": f.Claim, "refund": f.Refund} {
		t.Run(name, func(t *testing.T) {
			tx := transaction(t, v, f, name == "refund")
			if err := execute(tx, decode(t, f.Funding.PkScript, 34), f.Funding.Value); err != nil {
				t.Fatalf("synthetic spend failed the script engine: %v", err)
			}
		})
	}
}

func TestClaimMutationsReject(t *testing.T) {
	f := fixture(t)
	for _, name := range []string{"output-value", "output-destination", "prevout-amount", "prevout-key", "annex", "explicit-default-byte"} {
		t.Run(name, func(t *testing.T) {
			tx := transaction(t, f.Claim, f, false)
			pkScript, amount := decode(t, f.Funding.PkScript, 34), f.Funding.Value
			switch name {
			case "output-value":
				tx.TxOut[0].Value--
			case "output-destination":
				tx.TxOut[0].PkScript[2] ^= 1
			case "prevout-amount":
				amount++
			case "prevout-key":
				pkScript[2] ^= 1
			case "annex":
				tx.TxIn[0].Witness = append(tx.TxIn[0].Witness, []byte{0x50})
			case "explicit-default-byte":
				tx.TxIn[0].Witness[0] = append(tx.TxIn[0].Witness[0], 0)
			}
			if err := execute(tx, pkScript, amount); err == nil {
				t.Fatal("mutated claim unexpectedly passed script validation")
			}
		})
	}
}

func TestRefundCLTVAndCommitmentMutationsReject(t *testing.T) {
	f := fixture(t)
	for _, name := range []string{"below-cltv", "wrong-locktime-domain", "final-sequence", "leaf-script", "control-parity"} {
		t.Run(name, func(t *testing.T) {
			tx := transaction(t, f.Refund, f, true)
			cltvFailure := true
			switch name {
			case "below-cltv":
				tx.LockTime = f.Taproot.RefundLockTime - 1
			case "wrong-locktime-domain":
				tx.LockTime = txscript.LockTimeThreshold - 1
			case "final-sequence":
				tx.TxIn[0].Sequence = wire.MaxTxInSequenceNum
			case "leaf-script":
				tx.TxIn[0].Witness[1][1] ^= 1
				cltvFailure = false
			case "control-parity":
				tx.TxIn[0].Witness[2][0] ^= 1
				cltvFailure = false
			}
			err := execute(tx, decode(t, f.Funding.PkScript, 34), f.Funding.Value)
			if err == nil {
				t.Fatal("mutated refund unexpectedly passed script validation")
			}
			if cltvFailure && !txscript.IsErrorCode(err, txscript.ErrUnsatisfiedLockTime) {
				t.Fatal("expected a CLTV failure before signature verification")
			}
		})
	}
}

func TestScriptSuccessDoesNotEstablishTransactionFinality(t *testing.T) {
	f := fixture(t)
	tx := transaction(t, f.Refund, f, true)
	if err := execute(tx, decode(t, f.Funding.PkScript, 34), f.Funding.Value); err != nil {
		t.Fatal("baseline refund script rejected")
	}
	// This pure helper receives synthetic values; it does not obtain or validate
	// a real chain's median time. Script execution above has no MTP input at all.
	for _, offset := range []int64{-1, 0, 1} {
		mtp := time.Unix(int64(f.Taproot.RefundLockTime)+offset, 0)
		got := blockchain.IsFinalizedTransaction(btcutil.NewTx(tx), 100, mtp)
		if got != (offset > 0) {
			t.Fatal("timestamp finality must reject before/equal and accept after locktime")
		}
	}
}

func TestTransactionParserRejectsTruncationAndTrailingBytes(t *testing.T) {
	f := fixture(t)
	raw := decode(t, f.Claim.Raw, -1)
	for _, mutated := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
		if _, err := parseTransaction(mutated); err == nil {
			t.Fatal("noncanonical transaction bytes accepted")
		}
	}
}
