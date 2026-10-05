package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Public compatibility checks only. This is not application parsing, signing,
// authenticated root provisioning, current authority or admission policy.
const (
	governorAssignmentDomain = "PTLC/observation-governor-assignment/v1\x00"
	governorOwnerDomain      = "PTLC/observation-enrollment-owner-intent/v2\x00"
	governorRequestDomain    = "PTLC/observation-governor-signature-request/v1\x00"
)

func governorObject(value interface{}, fields []string) bool {
	object, ok := value.(map[string]interface{})
	if !ok || len(object) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return false
		}
	}
	return true
}

func governorHex(value interface{}, size int) ([]byte, bool) {
	text, ok := value.(string)
	if !ok || len(text) != size*2 || text != strings.ToLower(text) {
		return nil, false
	}
	body, err := hex.DecodeString(text)
	return body, err == nil
}

func governorNumber(value interface{}, maximum uint64) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	u, err := strconv.ParseUint(string(number), 10, 64)
	return err == nil && u > 0 && u <= maximum && strconv.FormatUint(u, 10) == string(number)
}

func governorDecode(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value map[string]interface{}
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func publicGovernorFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile("../qualification/fixtures/governor_signature.json")
	if err != nil {
		t.Fatal(err)
	}
	value := governorDecode(t, body)
	if len(value) != 12 || value["schema"] != "ptlc-governor-signature-public-vectors-v1" {
		t.Fatal("unexpected governor fixture shape")
	}
	return value
}

func governorCopy(t *testing.T, value interface{}) map[string]interface{} {
	return governorDecode(t, enrollmentCanonical(t, value))
}

func governorVerifies(t *testing.T, request map[string]interface{}) bool {
	t.Helper()
	if !governorObject(request, []string{"schema", "assignment", "bound_intent", "issuer_signature_hex", "owner_signature_hex"}) || request["schema"] != "ptlc-observation-governor-signature-request-v1" {
		return false
	}
	a, ok := request["assignment"].(map[string]interface{})
	if !ok || !governorObject(a, []string{"schema", "purpose", "algorithm", "issuer_auth_key_hex", "governor_profile"}) || a["schema"] != "ptlc-observation-governor-assignment-v1" || a["purpose"] != "observation-governor-assignment" || a["algorithm"] != "BIP340-SHA256" {
		return false
	}
	p, ok := a["governor_profile"].(map[string]interface{})
	if !ok || !governorObject(p, []string{"schema", "purpose", "role", "algorithm", "owner_auth_key_hex", "resource_digest_hex", "authority_id_hex", "authority_epoch", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex", "max_attempt_limit", "max_target_limit"}) || p["schema"] != "ptlc-observation-governor-profile-v1" || p["purpose"] != "observation-enrollment" || p["role"] != "enrollment-governor" || p["algorithm"] != "BIP340-SHA256" {
		return false
	}
	for _, field := range []string{"owner_auth_key_hex", "resource_digest_hex", "authority_id_hex", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex"} {
		if _, ok := governorHex(p[field], 32); !ok {
			return false
		}
	}
	if !governorNumber(p["authority_epoch"], (1<<53)-1) || !governorNumber(p["max_attempt_limit"], 64) || !governorNumber(p["max_target_limit"], 64) {
		return false
	}
	i, ok := request["bound_intent"].(map[string]interface{})
	if !ok || !governorObject(i, []string{"schema", "purpose", "role", "algorithm", "resource_digest_hex", "scope_digest_hex", "owner_auth_key_hex", "request_id_hex", "governor_assignment_digest_hex"}) || i["schema"] != "ptlc-observation-enrollment-intent-v2" || i["purpose"] != "observation-enrollment" || i["role"] != "enrollment-governor" || i["algorithm"] != "BIP340-SHA256" {
		return false
	}
	for _, field := range []string{"resource_digest_hex", "scope_digest_hex", "owner_auth_key_hex", "request_id_hex", "governor_assignment_digest_hex"} {
		if _, ok := governorHex(i[field], 32); !ok {
			return false
		}
	}
	issuerMessage := enrollmentHash(t, governorAssignmentDomain, a)
	if i["governor_assignment_digest_hex"] != hex.EncodeToString(issuerMessage) || i["owner_auth_key_hex"] != p["owner_auth_key_hex"] || i["resource_digest_hex"] != p["resource_digest_hex"] {
		return false
	}
	issuer, k1 := governorHex(a["issuer_auth_key_hex"], 32)
	owner, k2 := governorHex(i["owner_auth_key_hex"], 32)
	s1, s1ok := governorHex(request["issuer_signature_hex"], 64)
	s2, s2ok := governorHex(request["owner_signature_hex"], 64)
	return k1 && k2 && s1ok && s2ok && verifies(issuer, issuerMessage, s1) && verifies(owner, enrollmentHash(t, governorOwnerDomain, i), s2)
}

func TestGovernorPublicVectorsAndIndependentSignatureBindings(t *testing.T) {
	f := publicGovernorFixture(t)
	body, err := os.ReadFile("../qualification/fixtures/governor_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	unsigned := governorDecode(t, body)
	primary := f["primary"].(map[string]interface{})
	for _, field := range []string{"assignment", "assignment_digest_hex", "bound_intent", "bound_message_digest_hex"} {
		if !reflect.DeepEqual(primary[field], unsigned[field]) {
			t.Fatal("signed vectors changed the retained unsigned messages")
		}
	}
	for _, name := range []string{"primary", "alternate_issuer", "alternate_owner", "broader_caps", "new_epoch", "opaque_scope_under_caps", "same_key_roles"} {
		t.Run(name, func(t *testing.T) {
			v := f[name].(map[string]interface{})
			r := v["request"].(map[string]interface{})
			if !governorVerifies(t, r) || !reflect.DeepEqual(r["assignment"], v["assignment"]) || !reflect.DeepEqual(r["bound_intent"], v["bound_intent"]) || v["assignment_digest_hex"] != hex.EncodeToString(enrollmentHash(t, governorAssignmentDomain, r["assignment"])) || v["bound_message_digest_hex"] != hex.EncodeToString(enrollmentHash(t, governorOwnerDomain, r["bound_intent"])) {
				t.Fatal("independent governor signature or message mismatch")
			}
			result := v["result"].(map[string]interface{})
			if len(result) != 4 || result["schema"] != "ptlc-observation-governor-signature-result-v1" || result["issuer_signature_valid"] != true || result["owner_signature_valid"] != true || result["request_digest_hex"] != hex.EncodeToString(enrollmentHash(t, governorRequestDomain, r)) {
				t.Fatal("independent complete request digest mismatch")
			}
		})
	}
}

func TestGovernorEveryAssignmentProfileAndIntentFieldIsBound(t *testing.T) {
	r := publicGovernorFixture(t)["primary"].(map[string]interface{})["request"].(map[string]interface{})
	for _, path := range [][]string{{"assignment"}, {"assignment", "governor_profile"}, {"bound_intent"}} {
		object := r
		for _, field := range path {
			object = object[field].(map[string]interface{})
		}
		for field, value := range object {
			t.Run(strings.Join(path, "/")+"/"+field, func(t *testing.T) {
				changed := governorCopy(t, r)
				target := changed
				for _, field := range path {
					target = target[field].(map[string]interface{})
				}
				if number, ok := value.(json.Number); ok {
					u, _ := strconv.ParseUint(string(number), 10, 64)
					target[field] = json.Number(strconv.FormatUint(u+1, 10))
				} else {
					target[field] = strings.Repeat("99", 32)
				}
				if governorVerifies(t, changed) {
					t.Fatal("accepted changed signed governor binding")
				}
			})
		}
	}
}

func TestGovernorWrongRoleDomainAndLegacySignaturesRefuse(t *testing.T) {
	f := publicGovernorFixture(t)
	r := f["primary"].(map[string]interface{})["request"].(map[string]interface{})
	for _, value := range []struct{ field, alternate string }{{"issuer_signature_hex", "wrong_domain_issuer_signature_hex"}, {"owner_signature_hex", "wrong_domain_owner_signature_hex"}} {
		changed := governorCopy(t, r)
		changed[value.field] = f[value.alternate]
		if governorVerifies(t, changed) {
			t.Fatal("accepted signature in another domain")
		}
	}
	for _, field := range []string{"issuer_signature_hex", "owner_signature_hex"} {
		changed := governorCopy(t, r)
		other := "issuer_signature_hex"
		if field == other {
			other = "owner_signature_hex"
		}
		changed[field] = r[other]
		if governorVerifies(t, changed) {
			t.Fatal("accepted cross-role signature")
		}
	}
	changed := governorCopy(t, r)
	changed["owner_signature_hex"] = publicEnrollmentFixture(t).Request.SignatureHex
	if governorVerifies(t, changed) {
		t.Fatal("accepted legacy owner signature")
	}
}

func TestGovernorBothAlternateSignaturesChangeResultDigest(t *testing.T) {
	f := publicGovernorFixture(t)
	r := f["primary"].(map[string]interface{})["request"].(map[string]interface{})
	for _, role := range []string{"issuer", "owner"} {
		changed := governorCopy(t, r)
		changed[role+"_signature_hex"] = f["alternate_"+role+"_signature_hex"]
		if !governorVerifies(t, changed) || bytes.Equal(enrollmentHash(t, governorRequestDomain, changed), enrollmentHash(t, governorRequestDomain, r)) {
			t.Fatal("alternate public signature result binding mismatch")
		}
	}
}

func TestGovernorMalformedNumbersKeysAndSignaturesRefuse(t *testing.T) {
	r := publicGovernorFixture(t)["primary"].(map[string]interface{})["request"].(map[string]interface{})
	if !governorNumber(json.Number("9007199254740991"), (1<<53)-1) || !governorNumber(json.Number("64"), 64) || string(enrollmentCanonical(t, json.Number("9007199254740991"))) != "9007199254740991" {
		t.Fatal("integer boundaries or exact canonical integer bytes changed")
	}
	for _, field := range []string{"authority_epoch", "max_attempt_limit", "max_target_limit"} {
		for _, value := range []interface{}{true, "1", json.Number("1.0"), json.Number("1e0"), json.Number("0"), json.Number("-1"), json.Number("9007199254740992")} {
			changed := governorCopy(t, r)
			changed["assignment"].(map[string]interface{})["governor_profile"].(map[string]interface{})[field] = value
			if governorVerifies(t, changed) {
				t.Fatal("accepted invalid governor number")
			}
		}
	}
	for _, field := range []string{"issuer_signature_hex", "owner_signature_hex"} {
		for _, value := range []string{strings.Repeat("00", 64), strings.Repeat("ff", 32) + strings.Repeat("00", 32), strings.Repeat("00", 32) + strings.Repeat("ff", 32), strings.Repeat("00", 63), strings.Repeat("00", 65), strings.Repeat("ZZ", 64)} {
			changed := governorCopy(t, r)
			changed[field] = value
			if governorVerifies(t, changed) {
				t.Fatal("accepted malformed governor signature")
			}
		}
		for index := 0; index < 64; index++ {
			changed := governorCopy(t, r)
			signature := decode(t, r[field].(string))
			signature[index] ^= 1
			changed[field] = hex.EncodeToString(signature)
			if governorVerifies(t, changed) {
				t.Fatal("accepted mutated governor signature byte")
			}
		}
	}
	for _, invalid := range []string{strings.Repeat("00", 32), strings.Repeat("ff", 32)} {
		for _, issuer := range []bool{true, false} {
			changed := governorCopy(t, r)
			a := changed["assignment"].(map[string]interface{})
			i := changed["bound_intent"].(map[string]interface{})
			if issuer {
				a["issuer_auth_key_hex"] = invalid
			} else {
				a["governor_profile"].(map[string]interface{})["owner_auth_key_hex"] = invalid
				i["owner_auth_key_hex"] = invalid
			}
			i["governor_assignment_digest_hex"] = hex.EncodeToString(enrollmentHash(t, governorAssignmentDomain, a))
			if governorVerifies(t, changed) {
				t.Fatal("accepted curve-invalid governor key")
			}
		}
	}
}

func TestGovernorReplayAndOpaqueScopeDoNotEstablishCurrentPolicy(t *testing.T) {
	f := publicGovernorFixture(t)
	primary := f["primary"].(map[string]interface{})["request"].(map[string]interface{})
	opaque := f["opaque_scope_under_caps"].(map[string]interface{})["request"].(map[string]interface{})
	if primary["bound_intent"].(map[string]interface{})["scope_digest_hex"] != opaque["bound_intent"].(map[string]interface{})["scope_digest_hex"] || reflect.DeepEqual(primary["assignment"], opaque["assignment"]) {
		t.Fatal("opaque-scope limit control is missing")
	}
	for _, name := range []string{"primary", "new_epoch", "opaque_scope_under_caps", "same_key_roles"} {
		for i := 0; i < 3; i++ {
			if !governorVerifies(t, f[name].(map[string]interface{})["request"].(map[string]interface{})) {
				t.Fatal("unexpected signature-only refusal")
			}
		}
	}
}
