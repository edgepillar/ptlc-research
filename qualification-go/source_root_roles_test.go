package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Public mathematical compatibility only. A packet-selected root has no trusted
// governance role here; no signer, policy service or application gate is added.
const sourceRootDomain = "PTLC/observation-source-root-declaration/v1\x00"
const sourceRootRequestDomain = "PTLC/observation-source-root-request/v1\x00"

func publicSourceRootFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile("../qualification/fixtures/source_root_roles.json")
	if err != nil {
		t.Fatal(err)
	}
	v := governorDecode(t, body)
	if len(v) != 6 || v["schema"] != "ptlc-source-root-public-vectors-v1" {
		t.Fatal("unexpected source root fixture")
	}
	return v
}

func sourceRootVerifies(t *testing.T, request map[string]interface{}) bool {
	t.Helper()
	if !governorObject(request, []string{"schema", "declaration", "root_signature_hex"}) || request["schema"] != "ptlc-observation-source-root-request-v1" {
		return false
	}
	d, ok := request["declaration"].(map[string]interface{})
	if !ok || !governorObject(d, []string{"schema", "purpose", "algorithm", "declaration_revision", "source_context", "governor_profile", "delegated_keys", "root_transition"}) || d["schema"] != "ptlc-observation-source-root-declaration-v1" || d["purpose"] != "source-role-declaration" || d["algorithm"] != "BIP340-SHA256" || d["root_transition"] != "independent-reprovisioning" || !governorNumber(d["declaration_revision"], (1<<53)-1) {
		return false
	}
	s, ok := d["source_context"].(map[string]interface{})
	if !ok || !governorObject(s, []string{"schema", "source_id_hex", "source_profile_digest_hex", "source_incarnation_hex", "provisioning_root_key_hex", "resource_digest_hex", "authority_id_hex", "role"}) || s["schema"] != "ptlc-observation-policy-source-context-v1" || s["role"] != "enrollment-governor" {
		return false
	}
	for _, f := range []string{"source_id_hex", "source_profile_digest_hex", "source_incarnation_hex", "provisioning_root_key_hex", "resource_digest_hex", "authority_id_hex"} {
		if _, ok := governorHex(s[f], 32); !ok {
			return false
		}
	}
	p, ok := d["governor_profile"].(map[string]interface{})
	if !ok || !governorObject(p, []string{"schema", "purpose", "role", "algorithm", "owner_auth_key_hex", "resource_digest_hex", "authority_id_hex", "authority_epoch", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex", "max_attempt_limit", "max_target_limit"}) || p["schema"] != "ptlc-observation-governor-profile-v1" || p["purpose"] != "observation-enrollment" || p["role"] != "enrollment-governor" || p["algorithm"] != "BIP340-SHA256" {
		return false
	}
	for _, f := range []string{"owner_auth_key_hex", "resource_digest_hex", "authority_id_hex", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex"} {
		if _, ok := governorHex(p[f], 32); !ok {
			return false
		}
	}
	if !governorNumber(p["authority_epoch"], (1<<53)-1) || !governorNumber(p["max_attempt_limit"], 64) || !governorNumber(p["max_target_limit"], 64) {
		return false
	}
	for _, f := range []string{"authority_id_hex", "resource_digest_hex", "role"} {
		if s[f] != p[f] {
			return false
		}
	}
	roles, ok := d["delegated_keys"].(map[string]interface{})
	if !ok || !governorObject(roles, []string{"policy_admin_key_hex", "source_response_key_hex", "governor_issuer_key_hex"}) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range []interface{}{s["provisioning_root_key_hex"], p["owner_auth_key_hex"], roles["policy_admin_key_hex"], roles["source_response_key_hex"], roles["governor_issuer_key_hex"]} {
		b, ok := governorHex(v, 32)
		if !ok {
			return false
		}
		key := hex.EncodeToString(b)
		if seen[key] {
			return false
		}
		seen[key] = true
		if _, err := schnorr.ParsePubKey(b); err != nil {
			return false
		}
	}
	k, _ := governorHex(s["provisioning_root_key_hex"], 32)
	sig, ok := governorHex(request["root_signature_hex"], 64)
	return ok && verifies(k, enrollmentHash(t, sourceRootDomain, d), sig)
}

func sourceRootWire(t *testing.T, wire []byte) bool {
	t.Helper()
	if len(wire) == 0 || len(wire) > 8192 {
		return false
	}
	for _, b := range wire {
		if b > 127 {
			return false
		}
	}
	wire = bytes.TrimSuffix(wire, []byte("\n"))
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	var request map[string]interface{}
	if err := decoder.Decode(&request); err != nil {
		return false
	}
	return bytes.Equal(enrollmentCanonical(t, request), wire) && sourceRootVerifies(t, request)
}

func TestSourceRootPublicDeclarationsDomainsAndResults(t *testing.T) {
	vectors := publicSourceRootFixture(t)["positive_vectors"].(map[string]interface{})
	if len(vectors) != 10 {
		t.Fatal("unexpected positive vector count")
	}
	for name, value := range vectors {
		t.Run(name, func(t *testing.T) {
			v := value.(map[string]interface{})
			request := v["request"].(map[string]interface{})
			if !sourceRootVerifies(t, request) || !sourceRootWire(t, enrollmentCanonical(t, request)) {
				t.Fatal("valid public statement refused")
			}
			if hex.EncodeToString(enrollmentHash(t, sourceRootDomain, v["declaration"])) != v["message_digest_hex"] {
				t.Fatal("declaration digest mismatch")
			}
			result := v["result"].(map[string]interface{})
			if !governorObject(result, []string{"schema", "request_digest_hex", "root_signature_valid"}) || result["schema"] != "ptlc-observation-source-root-result-v1" || result["root_signature_valid"] != true || result["request_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceRootRequestDomain, request)) {
				t.Fatal("complete result mismatch")
			}
		})
	}
}

func TestSourceRootAllFieldsAndExactObjectsAreBound(t *testing.T) {
	request := publicSourceRootFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"]
	for _, path := range [][]string{{}, {"declaration"}, {"declaration", "source_context"}, {"declaration", "governor_profile"}, {"declaration", "delegated_keys"}} {
		fields := governorCopy(t, request)
		for _, p := range path {
			fields = fields[p].(map[string]interface{})
		}
		for f := range fields {
			for _, mode := range []string{"missing", "changed", "wrong-type"} {
				r := governorCopy(t, request)
				target := r
				for _, p := range path {
					target = target[p].(map[string]interface{})
				}
				switch mode {
				case "missing":
					delete(target, f)
				case "changed":
					target[f] = strings.Repeat("99", 32)
				case "wrong-type":
					target[f] = true
				}
				if sourceRootVerifies(t, r) {
					t.Fatalf("unbound field %v/%s/%s", path, f, mode)
				}
			}
		}
		r := governorCopy(t, request)
		target := r
		for _, p := range path {
			target = target[p].(map[string]interface{})
		}
		target["authorized"] = true
		if sourceRootVerifies(t, r) {
			t.Fatal("extra authorization claim accepted")
		}
	}
}

func TestSourceRootFiveKeysCurveMembershipCollisionsAndNumericAliases(t *testing.T) {
	f := publicSourceRootFixture(t)
	request := f["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"]
	paths := [][]string{{"source_context", "provisioning_root_key_hex"}, {"governor_profile", "owner_auth_key_hex"}, {"delegated_keys", "policy_admin_key_hex"}, {"delegated_keys", "source_response_key_hex"}, {"delegated_keys", "governor_issuer_key_hex"}}
	for _, p := range paths {
		for _, bad := range []string{strings.Repeat("00", 32), strings.Repeat("ff", 32), strings.Repeat("AB", 32), strings.Repeat("00", 31)} {
			r := governorCopy(t, request)
			r["declaration"].(map[string]interface{})[p[0]].(map[string]interface{})[p[1]] = bad
			if sourceRootVerifies(t, r) {
				t.Fatal("invalid role key accepted")
			}
		}
	}
	if sourceRootVerifies(t, f["role_collision"].(map[string]interface{})["request"].(map[string]interface{})) {
		t.Fatal("role collision accepted")
	}
	for _, p := range [][]string{{"declaration_revision"}, {"governor_profile", "authority_epoch"}, {"governor_profile", "max_attempt_limit"}, {"governor_profile", "max_target_limit"}} {
		for _, bad := range []interface{}{true, json.Number("0"), json.Number("-1"), json.Number("1.0"), json.Number("1e0"), json.Number("9007199254740992"), "1"} {
			r := governorCopy(t, request)
			d := r["declaration"].(map[string]interface{})
			if len(p) == 2 {
				d = d[p[0]].(map[string]interface{})
			}
			d[p[len(p)-1]] = bad
			if sourceRootVerifies(t, r) {
				t.Fatal("numeric alias accepted")
			}
		}
	}
}

func TestSourceRootWrongDomainKeyScalarAndEverySignatureByteRefuse(t *testing.T) {
	f := publicSourceRootFixture(t)
	request := f["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"].(map[string]interface{})
	bad := []string{f["wrong_domain_root_signature_hex"].(string), f["wrong_signing_key_signature_hex"].(string), strings.Repeat("00", 64), strings.Repeat("ff", 64), strings.Repeat("ff", 32) + strings.Repeat("00", 32), strings.Repeat("00", 32) + strings.Repeat("ff", 32)}
	original, _ := hex.DecodeString(request["root_signature_hex"].(string))
	for i := range original {
		changed := append([]byte{}, original...)
		changed[i] ^= 1
		bad = append(bad, hex.EncodeToString(changed))
	}
	for _, signature := range bad {
		r := governorCopy(t, request)
		r["root_signature_hex"] = signature
		if sourceRootVerifies(t, r) {
			t.Fatal("invalid signature accepted")
		}
	}
}

func TestSourceRootSignatureVariantChangesCompleteRequestDigest(t *testing.T) {
	f := publicSourceRootFixture(t)
	request := f["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"]
	r := governorCopy(t, request)
	r["root_signature_hex"] = f["alternate_root_signature_hex"]
	if !sourceRootVerifies(t, r) || bytes.Equal(enrollmentHash(t, sourceRootRequestDomain, r), enrollmentHash(t, sourceRootRequestDomain, request)) {
		t.Fatal("alternate complete signature binding failed")
	}
}

func TestSourceRootCanonicalWireAndSelfSelectedReplayRemainHistorical(t *testing.T) {
	vectors := publicSourceRootFixture(t)["positive_vectors"].(map[string]interface{})
	old := vectors["primary"].(map[string]interface{})["request"].(map[string]interface{})
	wire := enrollmentCanonical(t, old)
	for _, bad := range [][]byte{nil, []byte(strings.Repeat(" ", 8193)), append(append([]byte{}, wire...), '\n', '\n'), append([]byte(" "), wire...), []byte("\xff"), bytes.Replace(wire, []byte(`"declaration":`), []byte(`"\u0064eclaration":`), 1), bytes.Replace(wire, []byte(`"declaration_revision":1`), []byte(`"declaration_revision":1,"declaration_revision":1`), 1), bytes.Replace(wire, []byte(`"declaration_revision":1`), []byte(`"declaration_revision":1e0`), 1)} {
		if sourceRootWire(t, bad) {
			t.Fatal("noncanonical wire accepted")
		}
	}
	for _, name := range []string{"alternate_root", "alternate_admin", "alternate_response", "new_revision", "new_incarnation", "new_epoch"} {
		newer := vectors[name].(map[string]interface{})["request"].(map[string]interface{})
		if !sourceRootVerifies(t, newer) || !sourceRootVerifies(t, old) || !sourceRootVerifies(t, governorCopy(t, old)) {
			t.Fatal("historical math unexpectedly became a freshness decision")
		}
	}
	if !sourceRootWire(t, append(append([]byte{}, wire...), '\n')) {
		t.Fatal("one line terminator refused")
	}
}
