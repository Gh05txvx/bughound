package recon

import (
	"context"
	"testing"
)

func TestMockPipelineDiscovers(t *testing.T) {
	assets, err := MockPipeline{}.Discover(context.Background(), []string{"demo.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) == 0 {
		t.Fatal("must find assets")
	}
	var hasAppHost, hasAppURL, hasEvil, hasAdmin bool
	for _, a := range assets {
		switch a.Value {
		case "app.demo.test":
			hasAppHost = true
		case "https://app.demo.test/login":
			hasAppURL = true
		case "https://exfil.evil.test/":
			hasEvil = true
		case "admin.demo.test":
			hasAdmin = true
		}
	}
	if !hasAppHost || !hasAppURL {
		t.Error("subfinder/katana must find app.demo.test")
	}
	if !hasAdmin {
		t.Error("must find admin.demo.test (for the out-of-scope test)")
	}
	if !hasEvil {
		t.Error("the pipeline must include an out-of-scope asset for the filter test")
	}
}

func TestMockPipelineHasAllSources(t *testing.T) {
	assets, _ := MockPipeline{}.Discover(context.Background(), []string{"demo.test"})
	seen := map[string]bool{}
	for _, a := range assets {
		seen[a.Source] = true
	}
	for _, s := range []string{"subfinder", "gau", "dnsx", "httpx", "naabu", "katana"} {
		if !seen[s] {
			t.Errorf("the mock must include source %q", s)
		}
	}
}

func TestMockPipelineEmptySeeds(t *testing.T) {
	assets, err := MockPipeline{}.Discover(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 0 {
		t.Errorf("without seeds there must be no assets, got %d", len(assets))
	}
}
