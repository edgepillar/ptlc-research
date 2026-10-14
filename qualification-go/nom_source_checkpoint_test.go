package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Independent public mathematics only. A packet-selected root and an old signed
// custody statement establish neither source trust nor a nonrollback store.
const nomDeclarationDomain = "ptlc-nom-source-checkpoint-declaration-message-v1\x00"
const nomSourceDomain = "ptlc-nom-historical-source-message-v1\x00"
const nomCheckpointDomain = "ptlc-nom-historical-custody-message-v1\x00"
const nomRoleRequestDomain = "ptlc-nom-source-checkpoint-request-v1\x00"

func nomRoleFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile("../qualification/fixtures/nom_source_checkpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	f := governorDecode(t, body)
	if len(f) != 6 || f["schema"] != "ptlc-nom-source-checkpoint-public-vectors-v1" {
		t.Fatal("unexpected NoM role vectors")
	}
	return f
}

func nomRoleVerifies(t *testing.T, r map[string]interface{}) bool {
	t.Helper()
	if !governorObject(r, []string{"schema", "declaration", "source_statement", "checkpoint_statement", "root_signature_hex", "source_signature_hex", "checkpoint_signature_hex"}) || r["schema"] != "ptlc-nom-source-checkpoint-request-v1" {
		return false
	}
	d, ok := r["declaration"].(map[string]interface{})
	if !ok || !governorObject(d, []string{"schema", "purpose", "algorithm", "declaration_epoch", "network_selection", "root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex", "root_transition"}) || d["schema"] != "ptlc-nom-source-checkpoint-declaration-v1" || d["purpose"] != "historical-nom-source-and-custody-roles" || d["algorithm"] != "BIP340-SHA256" || d["root_transition"] != "independent-reprovisioning" || !governorNumber(d["declaration_epoch"], (1<<53)-1) {
		return false
	}
	n, ok := d["network_selection"].(map[string]interface{})
	if !ok || !governorObject(n, []string{"schema", "core_commit", "chain_id", "genesis_hash_hex", "binary_digest_hex", "spork_state_digest_hex", "authority_id_hex", "authority_profile_digest_hex", "authority_incarnation_hex", "provisioning_root_digest_hex", "canonicality_policy_digest_hex", "finality_policy_digest_hex", "freshness_policy_digest_hex", "restore_policy_digest_hex"}) || n["schema"] != "ptlc-nom-network-selection-v1" || n["core_commit"] != "45e1bbb48ce6fc19d44c5fbf59ccf5784981fced" {
		return false
	}
	chain, ok := n["chain_id"].(string)
	if !ok {
		return false
	}
	id, err := strconv.ParseUint(chain, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != chain {
		return false
	}
	for _, field := range []string{"genesis_hash_hex", "binary_digest_hex", "spork_state_digest_hex", "authority_id_hex", "authority_profile_digest_hex", "authority_incarnation_hex", "provisioning_root_digest_hex", "canonicality_policy_digest_hex", "finality_policy_digest_hex", "freshness_policy_digest_hex", "restore_policy_digest_hex"} {
		if _, ok := governorHex(n[field], 32); !ok {
			return false
		}
	}
	keys := make([][]byte, 0, 3)
	seen := map[string]bool{}
	for _, field := range []string{"root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex"} {
		key, ok := governorHex(d[field], 32)
		if !ok {
			return false
		}
		encoded := hex.EncodeToString(key)
		if seen[encoded] {
			return false
		}
		seen[encoded] = true
		if _, err := schnorr.ParsePubKey(key); err != nil {
			return false
		}
		keys = append(keys, key)
	}
	if n["provisioning_root_digest_hex"] != hex.EncodeToString(enrollmentBytesHash("ptlc-nom-selected-root-key-v1\x00", keys[0])) {
		return false
	}
	s, ok := r["source_statement"].(map[string]interface{})
	if !ok || !governorObject(s, []string{"schema", "purpose", "declaration_digest_hex", "binding_digest_hex", "query_digest_hex", "work_scope_digest_hex", "source_claim_digest_hex", "claim_coverage"}) || s["schema"] != "ptlc-nom-historical-source-statement-v1" || s["purpose"] != "historical-selected-capsule-source-claim" {
		return false
	}
	for _, field := range []string{"declaration_digest_hex", "binding_digest_hex", "query_digest_hex", "work_scope_digest_hex", "source_claim_digest_hex"} {
		if _, ok := governorHex(s[field], 32); !ok {
			return false
		}
	}
	switch s["claim_coverage"] {
	case "COMPLETE_CLAIM", "INCOMPLETE_CLAIM", "CONTRADICTED_CLAIM", "UNAVAILABLE_CLAIM":
	default:
		return false
	}
	c, ok := r["checkpoint_statement"].(map[string]interface{})
	if !ok || !governorObject(c, []string{"schema", "purpose", "declaration_digest_hex", "capsule_sha256", "journal_sha256", "journal_head_hex", "journal_sequence", "work_scope_digest_hex", "charged_work_digest_hex", "charged_work_count", "consumer_incarnation_hex", "observer_retention_selection_digest_hex", "observer_retention_head_digest_hex", "observer_retention_sequence", "external_checkpoint_digest_hex", "disclosure_possible", "work_outcome"}) || c["schema"] != "ptlc-nom-historical-custody-checkpoint-v1" || c["purpose"] != "historical-held-capsule-and-unknown-work" || c["work_outcome"] != "UNKNOWN" || c["disclosure_possible"] != true {
		return false
	}
	for _, field := range []string{"declaration_digest_hex", "capsule_sha256", "journal_sha256", "journal_head_hex", "work_scope_digest_hex", "charged_work_digest_hex", "consumer_incarnation_hex", "observer_retention_selection_digest_hex", "observer_retention_head_digest_hex", "external_checkpoint_digest_hex"} {
		if _, ok := governorHex(c[field], 32); !ok {
			return false
		}
	}
	for _, field := range []string{"journal_sequence", "charged_work_count", "observer_retention_sequence"} {
		if !governorNumber(c[field], (1<<53)-1) {
			return false
		}
	}
	digest := hex.EncodeToString(enrollmentHash(t, nomDeclarationDomain, d))
	if s["declaration_digest_hex"] != digest || c["declaration_digest_hex"] != digest || s["work_scope_digest_hex"] != c["work_scope_digest_hex"] {
		return false
	}
	for i, pair := range [][3]string{{nomDeclarationDomain, "declaration", "root_signature_hex"}, {nomSourceDomain, "source_statement", "source_signature_hex"}, {nomCheckpointDomain, "checkpoint_statement", "checkpoint_signature_hex"}} {
		sig, ok := governorHex(r[pair[2]], 64)
		if !ok || !verifies(keys[i], enrollmentHash(t, pair[0], r[pair[1]]), sig) {
			return false
		}
	}
	return true
}

func nomRoleWire(t *testing.T, input []byte) bool {
	t.Helper()
	if len(input) == 0 || len(input) > 8192 {
		return false
	}
	depth, quoted, escaped := 0, false, false
	for _, b := range input {
		if b > 127 {
			return false
		}
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
		} else if b == '"' {
			quoted = true
		} else if b == '[' || b == '{' {
			depth++
			if depth > 12 {
				return false
			}
		} else if b == ']' || b == '}' {
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	if quoted || depth != 0 {
		return false
	}
	wire := bytes.TrimSuffix(input, []byte("\n"))
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	var r map[string]interface{}
	if err := decoder.Decode(&r); err != nil {
		return false
	}
	return bytes.Equal(enrollmentCanonical(t, r), wire) && nomRoleVerifies(t, r)
}

func TestNoMSourceCheckpointThreeRolesPublicVectorsAndResultDigests(t *testing.T) {
	vectors := nomRoleFixture(t)["positive_vectors"].(map[string]interface{})
	if len(vectors) != 7 {
		t.Fatal("unexpected NoM role vector count")
	}
	for name, value := range vectors {
		t.Run(name, func(t *testing.T) {
			v := value.(map[string]interface{})
			r := v["request"].(map[string]interface{})
			if !nomRoleVerifies(t, r) || !nomRoleWire(t, enrollmentCanonical(t, r)) {
				t.Fatal("valid public mathematics refused")
			}
			messages := v["message_digests_hex"].(map[string]interface{})
			for _, p := range [][2]string{{nomDeclarationDomain, "declaration"}, {nomSourceDomain, "source_statement"}, {nomCheckpointDomain, "checkpoint_statement"}} {
				if messages[p[1]] != hex.EncodeToString(enrollmentHash(t, p[0], r[p[1]])) {
					t.Fatal("role digest mismatch")
				}
			}
			out := v["result"].(map[string]interface{})
			if !governorObject(out, []string{"schema", "request_digest_hex", "root_signature_valid", "source_signature_valid", "checkpoint_signature_valid"}) || out["schema"] != "ptlc-nom-source-checkpoint-result-v1" || out["request_digest_hex"] != hex.EncodeToString(enrollmentHash(t, nomRoleRequestDomain, r)) || out["root_signature_valid"] != true || out["source_signature_valid"] != true || out["checkpoint_signature_valid"] != true {
				t.Fatal("incomplete result")
			}
		})
	}
}

func TestNoMSourceCheckpointEveryFieldAndExactObjectIsBound(t *testing.T) {
	r := nomRoleFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"]
	for _, path := range [][]string{{}, {"declaration"}, {"declaration", "network_selection"}, {"source_statement"}, {"checkpoint_statement"}} {
		fields := governorCopy(t, r)
		for _, p := range path {
			fields = fields[p].(map[string]interface{})
		}
		for f := range fields {
			for _, mode := range []string{"missing", "changed", "wrong-type"} {
				changed := governorCopy(t, r)
				at := changed
				for _, p := range path {
					at = at[p].(map[string]interface{})
				}
				switch mode {
				case "missing":
					delete(at, f)
				case "changed":
					at[f] = strings.Repeat("99", 32)
				default:
					at[f] = []interface{}{}
				}
				if nomRoleVerifies(t, changed) {
					t.Fatalf("unbound %v/%s/%s", path, f, mode)
				}
			}
		}
		changed := governorCopy(t, r)
		at := changed
		for _, p := range path {
			at = at[p].(map[string]interface{})
		}
		at["admitted"] = true
		if nomRoleVerifies(t, changed) {
			t.Fatal("extra admission claim")
		}
	}
}

func TestNoMSourceCheckpointWrongRoleDomainAndSignatureBytesRefuse(t *testing.T) {
	f := nomRoleFixture(t)
	r := f["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"]
	for _, field := range []string{"root_signature_hex", "source_signature_hex", "checkpoint_signature_hex"} {
		for _, group := range []string{"wrong_role_signatures", "wrong_domain_signatures"} {
			changed := governorCopy(t, r)
			changed[field] = f[group].(map[string]interface{})[field]
			if nomRoleVerifies(t, changed) {
				t.Fatal("wrong role or domain")
			}
		}
		for i := 0; i < 64; i++ {
			changed := governorCopy(t, r)
			signature, _ := governorHex(changed[field], 64)
			signature[i] ^= 1
			changed[field] = hex.EncodeToString(signature)
			if nomRoleVerifies(t, changed) {
				t.Fatal("changed signature")
			}
		}
		for _, bad := range []string{strings.Repeat("00", 64), strings.Repeat("ff", 64), strings.Repeat("AB", 64), strings.Repeat("00", 63)} {
			changed := governorCopy(t, r)
			changed[field] = bad
			if nomRoleVerifies(t, changed) {
				t.Fatal("invalid signature")
			}
		}
	}
}

func TestNoMSourceCheckpointCurveMembershipRoleCollisionsAndRootCommitment(t *testing.T) {
	r := nomRoleFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"]
	roles := []string{"root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex"}
	for _, field := range roles {
		for _, bad := range []string{strings.Repeat("00", 32), strings.Repeat("ff", 32), strings.Repeat("AB", 32), strings.Repeat("00", 31)} {
			changed := governorCopy(t, r)
			changed["declaration"].(map[string]interface{})[field] = bad
			if nomRoleVerifies(t, changed) {
				t.Fatal("invalid role key")
			}
		}
		for _, other := range roles {
			if other != field {
				changed := governorCopy(t, r)
				d := changed["declaration"].(map[string]interface{})
				d[field] = d[other]
				if nomRoleVerifies(t, changed) {
					t.Fatal("role collision")
				}
			}
		}
	}
	changed := governorCopy(t, r)
	changed["declaration"].(map[string]interface{})["network_selection"].(map[string]interface{})["provisioning_root_digest_hex"] = strings.Repeat("00", 32)
	if nomRoleVerifies(t, changed) {
		t.Fatal("unbound root commitment")
	}
}

func TestNoMSourceCheckpointNumericBooleanAndChainAliases(t *testing.T) {
	r := nomRoleFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"]
	for _, p := range [][2]string{{"declaration", "declaration_epoch"}, {"checkpoint_statement", "journal_sequence"}, {"checkpoint_statement", "charged_work_count"}, {"checkpoint_statement", "observer_retention_sequence"}} {
		for _, bad := range []interface{}{true, json.Number("0"), json.Number("-1"), json.Number("1.0"), json.Number("1e0"), json.Number("9007199254740992"), "1"} {
			changed := governorCopy(t, r)
			changed[p[0]].(map[string]interface{})[p[1]] = bad
			if nomRoleVerifies(t, changed) {
				t.Fatal("numeric alias")
			}
		}
	}
	for _, bad := range []interface{}{json.Number("1"), "true", false} {
		changed := governorCopy(t, r)
		changed["checkpoint_statement"].(map[string]interface{})["disclosure_possible"] = bad
		if nomRoleVerifies(t, changed) {
			t.Fatal("disclosure alias")
		}
	}
	for _, bad := range []interface{}{"0", "01", "18446744073709551616", json.Number("1")} {
		changed := governorCopy(t, r)
		changed["declaration"].(map[string]interface{})["network_selection"].(map[string]interface{})["chain_id"] = bad
		if nomRoleVerifies(t, changed) {
			t.Fatal("chain alias")
		}
	}
}

func TestNoMSourceCheckpointCanonicalWireBoundsAndDepth(t *testing.T) {
	r := nomRoleFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"]
	wire := string(enrollmentCanonical(t, r))
	for _, bad := range []string{"", strings.Repeat(" ", 8193), strings.Repeat("[", 13), wire + "\n\n", wire + " ", strings.ReplaceAll(wire, "\"schema\":", "\"\\u0073chema\":"), strings.ReplaceAll(wire, "\"declaration_epoch\":1", "\"declaration_epoch\":1,\"declaration_epoch\":1"), strings.ReplaceAll(wire, "\"declaration_epoch\":1", "\"declaration_epoch\":1e0"), strings.ReplaceAll(wire, "historical-nom", "historical-n\u00f6m")} {
		if nomRoleWire(t, []byte(bad)) {
			t.Fatal("noncanonical wire")
		}
	}
	if !nomRoleWire(t, []byte(wire+"\n")) {
		t.Fatal("single LF refused")
	}
}

func TestNoMSourceCheckpointAlternateValidSignatureChangesRequestDigest(t *testing.T) {
	f := nomRoleFixture(t)
	r := governorCopy(t, f["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"])
	old := enrollmentHash(t, nomRoleRequestDomain, r)
	r["source_signature_hex"] = f["alternate_source_signature_hex"]
	if !nomRoleVerifies(t, r) || bytes.Equal(old, enrollmentHash(t, nomRoleRequestDomain, r)) {
		t.Fatal("alternate valid signature did not bind complete request")
	}
}

func TestNoMSourceCheckpointChallengeDoesNotMintNewCheckpointOrWork(t *testing.T) {
	v := nomRoleFixture(t)["positive_vectors"].(map[string]interface{})
	a := v["primary"].(map[string]interface{})["request"].(map[string]interface{})
	b := v["new_challenge"].(map[string]interface{})["request"].(map[string]interface{})
	if bytes.Equal(enrollmentCanonical(t, a["source_statement"]), enrollmentCanonical(t, b["source_statement"])) || !bytes.Equal(enrollmentCanonical(t, a["checkpoint_statement"]), enrollmentCanonical(t, b["checkpoint_statement"])) || a["checkpoint_signature_hex"] != b["checkpoint_signature_hex"] {
		t.Fatal("challenge changed retained custody")
	}
	u := v["unavailable"].(map[string]interface{})["request"].(map[string]interface{})
	if !nomRoleVerifies(t, u) || u["source_statement"].(map[string]interface{})["claim_coverage"] != "UNAVAILABLE_CLAIM" || u["checkpoint_statement"].(map[string]interface{})["work_outcome"] != "UNKNOWN" {
		t.Fatal("unavailable historical statement lost unknown work")
	}
}
