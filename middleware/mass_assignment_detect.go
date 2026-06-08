package middleware

// v1.7 W4: denylist detection of privilege-escalation fields in a body.
//
// The allowlist filter (MassAssign) is the robust fix but needs a
// per-route field list, so it cannot be default-on. This detector is
// the default-on complement: it recursively scans a parsed body for a
// curated set of privilege/auth field NAMES a normal client request
// almost never sets. Mirrors arcis-node/src/sanitizers/mass-assignment.ts
// and arcis-python mass_assignment.detect_mass_assignment.

import (
	"encoding/json"
	"strings"
)

// SensitiveFieldNames is the default privilege-escalation field set,
// stored in normalized form (lowercased, separators stripped). These
// are fields a profile/signup update should never carry from the
// client. role / permissions are the canonical mass-assignment fields
// and the FP-risk ones; opt out per-route if your admin API
// legitimately accepts them.
var SensitiveFieldNames = map[string]bool{
	"isadmin":       true,
	"issuperuser":   true,
	"superuser":     true,
	"issuperadmin":  true,
	"superadmin":    true,
	"isstaff":       true,
	"isverified":    true,
	"isroot":        true,
	"isowner":       true,
	"role":          true,
	"roles":         true,
	"userrole":      true,
	"permission":    true,
	"permissions":   true,
	"privilege":     true,
	"privileges":    true,
	"accesslevel":   true,
	"accounttype":   true,
	"isactive":      true,
	"emailverified": true,
}

// MassAssignDetectResult is the outcome of scanning a body for
// privilege-escalation field names.
type MassAssignDetectResult struct {
	// Detected is true if a sensitive field name was found anywhere.
	Detected bool
	// Field is the offending field name (original casing), or "".
	Field string
}

// normalizeFieldKey lowercases and strips `_` and `-` so is_admin /
// isAdmin / is-admin all collapse to the same canonical form.
func normalizeFieldKey(key string) string {
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	return key
}

// DetectMassAssignment recursively scans a parsed body (the result of
// json.Unmarshal into interface{}) for privilege-escalation field
// names. Detection only. Recurses into nested maps and slices.
// Value-agnostic: the presence of the key is the signal. When
// sensitiveFields is nil, the package default set is used.
func DetectMassAssignment(body interface{}, sensitiveFields map[string]bool) MassAssignDetectResult {
	set := sensitiveFields
	if set == nil {
		set = SensitiveFieldNames
	}
	const maxDepth = 8
	field := walkMassAssign(body, set, 0, maxDepth)
	return MassAssignDetectResult{Detected: field != "", Field: field}
}

func walkMassAssign(value interface{}, set map[string]bool, depth, maxDepth int) string {
	if depth > maxDepth {
		return ""
	}
	switch v := value.(type) {
	case map[string]interface{}:
		for key := range v {
			if set[normalizeFieldKey(key)] {
				return key
			}
		}
		for _, child := range v {
			if hit := walkMassAssign(child, set, depth+1, maxDepth); hit != "" {
				return hit
			}
		}
	case []interface{}:
		for _, item := range v {
			if hit := walkMassAssign(item, set, depth+1, maxDepth); hit != "" {
				return hit
			}
		}
	}
	return ""
}

// DetectMassAssignmentJSON parses raw JSON bytes and runs the detector.
// Returns Detected=false on empty input or unparseable JSON ("not a
// structured body, nothing to check"). Convenience wrapper the adapters
// call after reading the request body.
func DetectMassAssignmentJSON(raw []byte, sensitiveFields map[string]bool) MassAssignDetectResult {
	if len(raw) == 0 {
		return MassAssignDetectResult{Detected: false}
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return MassAssignDetectResult{Detected: false}
	}
	return DetectMassAssignment(parsed, sensitiveFields)
}
