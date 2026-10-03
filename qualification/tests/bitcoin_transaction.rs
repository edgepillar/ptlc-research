//! Offline, synthetic transaction qualification; never a wallet or broadcaster.
//! rust-bitcoin owns consensus serialization, Taproot trees, and sighash encoding.

use std::str::FromStr;

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    consensus,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_DROP},
    script::Builder,
    secp256k1::{
        Keypair, Message, Parity, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature,
    },
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    transaction,
};
use musig2::{
    AggNonce, BinaryEncoding, KeyAggContext, LiftedSignature, PartialSignature, SecNonce, adaptor,
    secp::{MaybeScalar, Point, Scalar},
};

const REFUND_TIME: u32 = 500_000_100;
const INPUT_SATS: u64 = 200_000;
const OUTPUT_SATS: u64 = 199_000;
const FUNDING_TXID: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn scalar(tag: u8) -> Scalar {
    Scalar::from_slice(&[tag; 32]).unwrap()
}

fn keypair(tag: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[tag; 32]).unwrap(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn refund_script(time: u32, key: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(time))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

struct Contract {
    context: KeyAggContext,
    spend_info: TaprootSpendInfo,
    refund_key: Keypair,
    script: ScriptBuf,
    control: ControlBlock,
    prevout: TxOut,
}

fn contract(key_tags: [u8; 2], refund_tag: u8) -> Contract {
    let context = KeyAggContext::new(key_tags.map(|tag| scalar(tag).base_point_mul())).unwrap();
    let internal: Point = context.aggregated_pubkey();
    let internal_key = XOnlyPublicKey::from_slice(&internal.serialize_xonly()).unwrap();
    let refund_key = keypair(refund_tag);
    let script = refund_script(REFUND_TIME, refund_key.x_only_public_key().0);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&Secp256k1::new(), internal_key)
        .unwrap();
    let root = spend_info.merkle_root().unwrap().to_byte_array();
    let context = context.with_taproot_tweak(&root).unwrap();
    let output: Point = context.aggregated_pubkey();
    assert_eq!(
        output.serialize_xonly(),
        spend_info.output_key().serialize()
    );
    assert_eq!(
        output.has_even_y(),
        spend_info.output_key_parity() == Parity::Even,
        "both libraries must agree on full output-key parity"
    );
    let control = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap();
    assert_eq!(
        control.serialize().len(),
        33,
        "single leaf, no Merkle siblings"
    );
    assert!(control.verify_taproot_commitment(
        &Secp256k1::verification_only(),
        spend_info.output_key().to_x_only_public_key(),
        &script
    ));
    let prevout = TxOut {
        value: Amount::from_sat(INPUT_SATS),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
    };
    Contract {
        context,
        spend_info,
        refund_key,
        script,
        control,
        prevout,
    }
}

fn unsigned_transaction(lock_time: absolute::LockTime, destination_tag: u8) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(FUNDING_TXID).unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(OUTPUT_SATS),
            script_pubkey: ScriptBuf::new_p2tr(
                &Secp256k1::new(),
                keypair(destination_tag).x_only_public_key().0,
                None,
            ),
        }],
    }
}

fn claim_digest(tx: &Transaction, prevout: &TxOut) -> [u8; 32] {
    SighashCache::new(tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
        .unwrap()
        .to_byte_array()
}

fn refund_digest(tx: &Transaction, prevout: &TxOut, script: &ScriptBuf) -> [u8; 32] {
    SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            TapLeafHash::from_script(script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap()
        .to_byte_array()
}

fn verifies(key: XOnlyPublicKey, digest: [u8; 32], signature: &[u8]) -> bool {
    Signature::from_slice(signature).is_ok_and(|sig| {
        Secp256k1::verification_only()
            .verify_schnorr(&sig, &Message::from_digest(digest), &key)
            .is_ok()
    })
}

fn completed_claim(contract: &Contract, key_tags: [u8; 2]) -> Transaction {
    let mut tx = unsigned_transaction(absolute::LockTime::ZERO, 10);
    let message = claim_digest(&tx, &contract.prevout);
    let keys = key_tags.map(scalar);
    let witness = scalar(7);
    let adaptor_point = witness.base_point_mul();
    let aggregate: Point = contract.context.aggregated_pubkey();
    let nonces = [0, 1].map(|i| {
        SecNonce::generate(
            [21 + i as u8; 32],
            keys[i],
            aggregate,
            message,
            adaptor_point.serialize(),
        )
    });
    let pubnonces = nonces.each_ref().map(SecNonce::public_nonce);
    let agg_nonce = AggNonce::sum(&pubnonces);
    let partials: Vec<PartialSignature> = nonces
        .into_iter()
        .enumerate()
        .map(|(i, nonce)| {
            let partial = adaptor::sign_partial(
                &contract.context,
                keys[i],
                nonce,
                &agg_nonce,
                adaptor_point,
                message,
            )
            .unwrap();
            adaptor::verify_partial(
                &contract.context,
                partial,
                &agg_nonce,
                adaptor_point,
                keys[i].base_point_mul(),
                &pubnonces[i],
                message,
            )
            .unwrap();
            partial
        })
        .collect();
    let pre = adaptor::aggregate_partial_signatures(
        &contract.context,
        &agg_nonce,
        adaptor_point,
        partials,
        message,
    )
    .unwrap();
    // Retain and verify the complete adaptor pre-signature before releasing a final signature.
    adaptor::verify_single(aggregate, &pre, message, adaptor_point).unwrap();
    let complete: LiftedSignature = pre.adapt(witness).unwrap();
    let signature = complete.to_bytes();
    assert!(verifies(
        contract.spend_info.output_key().to_x_only_public_key(),
        message,
        &signature
    ));
    let recovered = pre.reveal_secret::<MaybeScalar>(&complete).unwrap();
    assert_eq!(recovered, witness.into());
    assert_eq!(recovered.base_point_mul(), adaptor_point.into());
    tx.input[0].witness = Witness::from_slice(&[signature]);
    assert_eq!(tx.input[0].witness.iter().next().unwrap().len(), 64);
    tx
}

fn completed_refund(contract: &Contract) -> Transaction {
    let mut tx = unsigned_transaction(absolute::LockTime::from_time(REFUND_TIME).unwrap(), 9);
    let message = refund_digest(&tx, &contract.prevout, &contract.script);
    // The refund signs with Alice's leaf key; Bob and the adaptor witness are not inputs.
    let signature = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&Message::from_digest(message), &contract.refund_key);
    assert!(verifies(
        contract.refund_key.x_only_public_key().0,
        message,
        signature.as_ref()
    ));
    tx.input[0].witness = Witness::from_slice(&[
        signature.as_ref().to_vec(),
        contract.script.to_bytes(),
        contract.control.serialize(),
    ]);
    tx
}

fn transaction_fields(tx: &Transaction, digest: [u8; 32]) -> serde_json::Value {
    let bytes = consensus::serialize(tx);
    let decoded: Transaction = consensus::deserialize(&bytes).unwrap();
    assert_eq!(decoded, *tx);
    serde_json::json!({
        "raw_tx_hex": hex(&bytes),
        "txid_hex": tx.compute_txid().to_string(),
        "wtxid_hex": tx.compute_wtxid().to_string(),
        "sighash_hex": hex(&digest),
        "version": tx.version.0,
        "sequence": tx.input[0].sequence.to_consensus_u32(),
        "locktime": tx.lock_time.to_consensus_u32(),
        "output_value_sats": tx.output[0].value.to_sat(),
        "destination_script_pubkey_hex": hex(tx.output[0].script_pubkey.as_bytes()),
    })
}

#[test]
fn transaction_fixture_matches_actual_adaptor_claim_and_unilateral_refund() {
    let contract = contract([1, 2], 9);
    let claim = completed_claim(&contract, [1, 2]);
    let refund = completed_refund(&contract);
    let fixture = serde_json::json!({
        "schema": "ptlc-bitcoin-transactions-v1",
        "note": "Public synthetic data only. Transactions are alternatives spending the same fictional output. Offline signature and commitment qualification; no funding, broadcast, MTP finality, fee adequacy, or chain-liveness claim.",
        "funding": {
            "txid_hex": FUNDING_TXID, "vout": 1, "value_sats": INPUT_SATS,
            "script_pubkey_hex": hex(contract.prevout.script_pubkey.as_bytes()),
        },
        "taproot": {
            "internal_key_xonly_hex": hex(&contract.spend_info.internal_key().serialize()),
            "output_key_xonly_hex": hex(&contract.spend_info.output_key().serialize()),
            "merkle_root_hex": hex(&contract.spend_info.merkle_root().unwrap().to_byte_array()),
            "tapleaf_hash_hex": hex(&TapLeafHash::from_script(&contract.script, LeafVersion::TapScript).to_byte_array()),
            "leaf_version": LeafVersion::TapScript.to_consensus(),
            "refund_key_xonly_hex": hex(&contract.refund_key.x_only_public_key().0.serialize()),
            "refund_leaf_script_hex": hex(contract.script.as_bytes()),
            "control_block_hex": hex(&contract.control.serialize()),
            "refund_locktime": REFUND_TIME,
        },
        "claim": transaction_fields(&claim, claim_digest(&claim, &contract.prevout)),
        "refund": transaction_fields(&refund, refund_digest(&refund, &contract.prevout, &contract.script)),
    });
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/bitcoin_transactions.json")).unwrap();
    assert_eq!(fixture, expected, "public transaction fixture changed");
}

#[test]
fn claim_signature_commits_to_output_and_prevout_value_and_script() {
    let contract = contract([1, 2], 9);
    let claim = completed_claim(&contract, [1, 2]);
    let signature = claim.input[0].witness.iter().next().unwrap();
    let key = contract.spend_info.output_key().to_x_only_public_key();
    let mut changed_output = claim.clone();
    changed_output.output[0].value = Amount::from_sat(OUTPUT_SATS - 1);
    assert!(!verifies(
        key,
        claim_digest(&changed_output, &contract.prevout),
        signature
    ));
    changed_output = claim.clone();
    changed_output.output[0].script_pubkey = contract.prevout.script_pubkey.clone();
    assert!(!verifies(
        key,
        claim_digest(&changed_output, &contract.prevout),
        signature
    ));
    let mut changed_prevout = contract.prevout.clone();
    changed_prevout.value = Amount::from_sat(INPUT_SATS + 1);
    assert!(!verifies(
        key,
        claim_digest(&claim, &changed_prevout),
        signature
    ));
    changed_prevout = contract.prevout.clone();
    changed_prevout.script_pubkey = claim.output[0].script_pubkey.clone();
    assert!(!verifies(
        key,
        claim_digest(&claim, &changed_prevout),
        signature
    ));
}

#[test]
fn refund_leaf_control_block_and_tweak_mutations_fail_commitment_or_signature() {
    let contract = contract([1, 2], 9);
    let claim = completed_claim(&contract, [1, 2]);
    let refund = completed_refund(&contract);
    let key = contract.spend_info.output_key().to_x_only_public_key();
    let secp = Secp256k1::verification_only();
    let changed_leaf = refund_script(REFUND_TIME + 1, contract.refund_key.x_only_public_key().0);
    assert!(
        !contract
            .control
            .verify_taproot_commitment(&secp, key, &changed_leaf)
    );
    let mut changed_control = contract.control.serialize();
    changed_control[0] ^= 1;
    assert!(
        !ControlBlock::decode(&changed_control)
            .unwrap()
            .verify_taproot_commitment(&secp, key, &contract.script)
    );
    let wrong_context =
        KeyAggContext::new([scalar(1).base_point_mul(), scalar(2).base_point_mul()])
            .unwrap()
            .with_taproot_tweak(&[0x55; 32])
            .unwrap();
    let wrong_point: Point = wrong_context.aggregated_pubkey();
    let wrong_key = XOnlyPublicKey::from_slice(&wrong_point.serialize_xonly()).unwrap();
    assert_ne!(key, wrong_key);
    assert!(!verifies(
        wrong_key,
        claim_digest(&claim, &contract.prevout),
        claim.input[0].witness.iter().next().unwrap()
    ));
    let refund_key = contract.refund_key.x_only_public_key().0;
    let signature = refund.input[0].witness.iter().next().unwrap();
    assert!(!verifies(
        refund_key,
        refund_digest(&refund, &contract.prevout, &changed_leaf),
        signature
    ));
    let mut earlier = refund.clone();
    earlier.lock_time = absolute::LockTime::from_time(REFUND_TIME - 1).unwrap();
    assert!(!verifies(
        refund_key,
        refund_digest(&earlier, &contract.prevout, &contract.script),
        signature
    ));
    let mut final_sequence = refund.clone();
    final_sequence.input[0].sequence = Sequence::MAX;
    assert!(!verifies(
        refund_key,
        refund_digest(&final_sequence, &contract.prevout, &contract.script),
        signature
    ));
    // These are signature/commitment negatives. CLTV execution and chain finality are separate.
}

#[test]
fn taproot_tweak_agrees_across_internal_and_output_key_parities() {
    let mut combinations = std::collections::BTreeSet::new();
    for tag in 1..=32 {
        let context =
            KeyAggContext::new([scalar(tag).base_point_mul(), scalar(40).base_point_mul()])
                .unwrap();
        let internal: Point = context.aggregated_pubkey();
        let contract = contract([tag, 40], 9);
        let _claim = completed_claim(&contract, [tag, 40]);
        combinations.insert((
            internal.has_even_y(),
            contract.spend_info.output_key_parity() == Parity::Even,
        ));
    }
    assert_eq!(
        combinations.len(),
        4,
        "cover even and odd internal/output parity combinations"
    );
}
