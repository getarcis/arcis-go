package intelligence

import (
	"reflect"
	"testing"
)

func TestOptionsFromEnv_UnsetEndpointIsInert(t *testing.T) {
	t.Setenv("ARCIS_INTEL_ENDPOINT", "")
	if _, ok := OptionsFromEnv(); ok {
		t.Fatal("expected ok=false when ARCIS_INTEL_ENDPOINT is unset")
	}
}

func TestOptionsFromEnv_FullConfig(t *testing.T) {
	t.Setenv("ARCIS_INTEL_ENDPOINT", "https://intel.example.com/")
	t.Setenv("ARCIS_INTEL_KEY", "secret-token")
	t.Setenv("ARCIS_INTEL_WORKSPACE", "ws-1")
	t.Setenv("ARCIS_INTEL_DECISIONS", "ip-rep, bot-corpus")
	t.Setenv("ARCIS_INTEL_BLOCK_THRESHOLD", "7")

	opts, ok := OptionsFromEnv()
	if !ok {
		t.Fatal("expected ok=true when endpoint is set")
	}
	if opts.Endpoint != "https://intel.example.com/" {
		t.Errorf("endpoint = %q", opts.Endpoint)
	}
	if opts.APIKey != "secret-token" {
		t.Errorf("apiKey = %q", opts.APIKey)
	}
	if opts.WorkspaceID != "ws-1" {
		t.Errorf("workspaceID = %q", opts.WorkspaceID)
	}
	if !reflect.DeepEqual(opts.CloudDecisions, []string{"ip-rep", "bot-corpus"}) {
		t.Errorf("cloudDecisions = %v", opts.CloudDecisions)
	}
	if opts.BlockThreshold != 7 {
		t.Errorf("blockThreshold = %d, want 7", opts.BlockThreshold)
	}
}

func TestOptionsFromEnv_FiltersUnknownDecisions(t *testing.T) {
	t.Setenv("ARCIS_INTEL_ENDPOINT", "https://intel.example.com")
	t.Setenv("ARCIS_INTEL_DECISIONS", "ip-rep,bogus,,bot-corpus,xss")

	opts, ok := OptionsFromEnv()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !reflect.DeepEqual(opts.CloudDecisions, []string{"ip-rep", "bot-corpus"}) {
		t.Errorf("expected only valid decisions, got %v", opts.CloudDecisions)
	}
}

func TestOptionsFromEnv_InvalidThresholdIsObserveOnly(t *testing.T) {
	t.Setenv("ARCIS_INTEL_ENDPOINT", "https://intel.example.com")
	t.Setenv("ARCIS_INTEL_BLOCK_THRESHOLD", "not-a-number")

	opts, ok := OptionsFromEnv()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if opts.BlockThreshold != 0 {
		t.Errorf("expected observe-only (0) on invalid threshold, got %d", opts.BlockThreshold)
	}
}

func TestOptionsFromEnv_BuildsValidClient(t *testing.T) {
	t.Setenv("ARCIS_INTEL_ENDPOINT", "https://intel.example.com")
	t.Setenv("ARCIS_INTEL_DECISIONS", "ip-rep")

	opts, ok := OptionsFromEnv()
	if !ok {
		t.Fatal("expected ok=true")
	}
	client, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient from env options: %v", err)
	}
	defer client.Close()
	if client.BotCorpusEnabled() {
		t.Error("bot-corpus should be off (only ip-rep requested)")
	}
}
