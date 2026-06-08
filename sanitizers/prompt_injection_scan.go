package sanitizers

// v1.7 W6: recursively scan a parsed request body for prompt-injection
// signatures. Mirrors the Node + Python body-scan wire-up helpers.

import "encoding/json"

var promptSeverityRank = map[string]int{
	"none":   0,
	"low":    1,
	"medium": 2,
	"high":   3,
}

// ScanPromptInjection recursively walks a parsed body (the result of
// json.Unmarshal into interface{}) and runs DetectPromptInjection on
// every string value. Returns true if any string matches at or above
// minSeverity (one of "low", "medium", "high"; defaults to "medium"
// when unrecognized).
func ScanPromptInjection(body interface{}, minSeverity string) bool {
	minRank, ok := promptSeverityRank[minSeverity]
	if !ok {
		minRank = 2 // medium
	}
	return walkPromptInjection(body, minRank, 0)
}

func walkPromptInjection(value interface{}, minRank, depth int) bool {
	if depth > 8 {
		return false
	}
	switch v := value.(type) {
	case string:
		res := DetectPromptInjection(v)
		return res.Detected && promptSeverityRank[res.Severity] >= minRank
	case map[string]interface{}:
		for _, child := range v {
			if walkPromptInjection(child, minRank, depth+1) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if walkPromptInjection(item, minRank, depth+1) {
				return true
			}
		}
	}
	return false
}

// ScanPromptInjectionJSON parses raw JSON bytes and runs
// ScanPromptInjection. Returns false on empty input or unparseable JSON.
// Convenience wrapper the adapters call after reading the request body.
func ScanPromptInjectionJSON(raw []byte, minSeverity string) bool {
	if len(raw) == 0 {
		return false
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	return ScanPromptInjection(parsed, minSeverity)
}
