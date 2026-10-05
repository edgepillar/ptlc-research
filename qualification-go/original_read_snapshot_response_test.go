package qualification

import (
	"encoding/hex"
	"os"
	"reflect"
	"testing"
)

// Test-only public compatibility; these signed claims are never source truth.
func snapshotResponseFixture(t *testing.T, input bool) map[string]interface{} {
	t.Helper()
	name := "../qualification/fixtures/original_read_snapshot_response.json"
	schema := "ptlc-original-read-snapshot-response-public-vectors-v1"
	if input {
		name = "../qualification/fixtures/original_read_snapshot_inputs.json"
		schema = "ptlc-original-read-snapshot-inputs-v1"
	}
	wire, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	f := governorDecode(t, wire)
	if len(f) != 4 || f["schema"] != schema || f["purpose"] != "offline-owned-snapshot-binding-only" {
		t.Fatal("unexpected synthetic snapshot fixture")
	}
	return f
}

func TestSnapshotResponseTenSamplesAndSixCounterclaimsUseExistingPublicGrammar(t *testing.T) {
	f := snapshotResponseFixture(t, false)
	for group, count := range map[string]int{"positive_vectors": 10, "counterclaim_vectors": 6} {
		vectors := f[group].(map[string]interface{})
		if len(vectors) != count {
			t.Fatal("unexpected synthetic vector count")
		}
		for name, item := range vectors {
			v := item.(map[string]interface{})
			p := v["request"].(map[string]interface{})
			if !originalReadResponseVerifies(t, p) || !originalReadResponseWire(t, enrollmentCanonical(t, p)) {
				t.Fatal(name, "public historical math refused")
			}
			if v["message_digest_hex"] != hex.EncodeToString(originalReadResponseMessage(t, v["response"])) {
				t.Fatal(name, "message differs")
			}
			result := v["result"].(map[string]interface{})
			if len(result) != 4 || result["schema"] != "ptlc-observation-original-read-response-result-v1" || result["request_digest_hex"] != hex.EncodeToString(enrollmentHash(t, originalReadResponseRequestDomain, p)) || result["root_signature_valid"] != true || result["response_signature_valid"] != true {
				t.Fatal(name, "complete two-flag result differs")
			}
		}
	}
}

func TestSnapshotResponseSyntheticRetainedRowsCommitToPolicyAndRecordHeads(t *testing.T) {
	f := snapshotResponseFixture(t, true)
	for name, item := range f["positive_vectors"].(map[string]interface{}) {
		v := item.(map[string]interface{})
		rows := v["record_material"].(map[string]interface{})
		q := v["response"].(map[string]interface{})["query"].(map[string]interface{})
		record := q["expected_record_checkpoint"].(map[string]interface{})
		if record["record_lineage_digest_hex"] != hex.EncodeToString(enrollmentHash(t, "PTLC/offline-local-original-record-lineage/v1\x00", rows)) {
			t.Fatal(name, "retained rows differ")
		}
		source := rows["source"].(map[string]interface{})
		state := map[string]interface{}{"root_declaration": rows["root_declaration"], "revision": source["revision"], "profile_hex": source["profile_hex"], "active": source["active"], "mode": source["mode"]}
		policy := q["expected_checkpoint"].(map[string]interface{})
		if policy["policy_state_digest_hex"] != hex.EncodeToString(enrollmentHash(t, "PTLC/offline-local-policy-read-state/v1\x00", state)) || policy["revision"] != source["revision"] {
			t.Fatal(name, "policy head differs")
		}
	}
}

func TestSnapshotResponseEveryByteOfBothSignaturesRefuses(t *testing.T) {
	f := snapshotResponseFixture(t, false)
	for _, group := range []string{"positive_vectors", "counterclaim_vectors"} {
		for name, item := range f[group].(map[string]interface{}) {
			v := item.(map[string]interface{})
			for _, root := range []bool{false, true} {
				for b := 0; b < 64; b++ {
					p := governorCopy(t, v["request"].(map[string]interface{}))
					m, field := p, "response_signature_hex"
					if root {
						m, field = p["root_envelope"].(map[string]interface{}), "root_signature_hex"
					}
					s := []byte(m[field].(string))
					if s[b*2] == '0' {
						s[b*2] = '1'
					} else {
						s[b*2] = '0'
					}
					m[field] = string(s)
					if originalReadResponseVerifies(t, p) {
						t.Fatal(name, "changed signature accepted")
					}
				}
			}
		}
	}
}

func TestSnapshotResponseValidCounterclaimsStillDifferFromOwnedSample(t *testing.T) {
	f := snapshotResponseFixture(t, false)
	positive := f["positive_vectors"].(map[string]interface{})
	for name, item := range f["counterclaim_vectors"].(map[string]interface{}) {
		v := item.(map[string]interface{})
		actual := positive[v["actual_scenario"].(string)].(map[string]interface{})
		if reflect.DeepEqual(v["response"], actual["response"]) || reflect.DeepEqual(v["result"], actual["result"]) || !originalReadResponseVerifies(t, v["request"].(map[string]interface{})) {
			t.Fatal(name, "counterclaim boundary differs")
		}
	}
}
