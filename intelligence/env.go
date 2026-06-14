package intelligence

import (
	"os"
	"strconv"
	"strings"
)

// OptionsFromEnv builds Options from ARCIS_INTEL_* environment variables for
// 12-factor configuration, returning ok=false when ARCIS_INTEL_ENDPOINT is
// unset so the caller leaves cloud intelligence off (zero network work).
// Mirrors the Node resolveIntelligenceOptions / Python _intelligence_from_env
// fallback so the same env config activates intelligence in every SDK.
//
//	ARCIS_INTEL_ENDPOINT         required to activate the env path
//	ARCIS_INTEL_KEY              optional bearer token
//	ARCIS_INTEL_WORKSPACE        optional workspace id
//	ARCIS_INTEL_DECISIONS        comma list: "ip-rep,bot-corpus"
//	ARCIS_INTEL_BLOCK_THRESHOLD  optional int; reputation severity at/above
//	                             which to block (omit / invalid = observe-only)
//
// Typical use, wiring the result into an adapter Config:
//
//	if opts, ok := intelligence.OptionsFromEnv(); ok {
//		if client, err := intelligence.NewClient(opts); err == nil {
//			cfg.Intelligence = client
//			cfg.IntelligenceBlockThreshold = opts.BlockThreshold
//		}
//	}
func OptionsFromEnv() (Options, bool) {
	endpoint := os.Getenv("ARCIS_INTEL_ENDPOINT")
	if endpoint == "" {
		return Options{}, false
	}

	var decisions []string
	for _, d := range strings.Split(os.Getenv("ARCIS_INTEL_DECISIONS"), ",") {
		switch strings.TrimSpace(d) {
		case "ip-rep":
			decisions = append(decisions, "ip-rep")
		case "bot-corpus":
			decisions = append(decisions, "bot-corpus")
		}
	}

	// Invalid / missing threshold falls back to 0 (observe-only), matching the
	// Node/Python "omit = annotate only" semantics.
	blockThreshold := 0
	if raw := os.Getenv("ARCIS_INTEL_BLOCK_THRESHOLD"); raw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			blockThreshold = n
		}
	}

	return Options{
		Endpoint:       endpoint,
		APIKey:         os.Getenv("ARCIS_INTEL_KEY"),
		WorkspaceID:    os.Getenv("ARCIS_INTEL_WORKSPACE"),
		CloudDecisions: decisions,
		BlockThreshold: blockThreshold,
	}, true
}
