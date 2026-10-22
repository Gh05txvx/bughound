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
		t.Fatal("harus menemukan aset")
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
		t.Error("subfinder/katana harus menemukan app.demo.test")
	}
	if !hasAdmin {
		t.Error("harus menemukan admin.demo.test (untuk uji out-of-scope)")
	}
	if !hasEvil {
		t.Error("pipeline harus menyertakan aset di luar scope untuk uji filter")
	}
}

func TestMockPipelineEmptySeeds(t *testing.T) {
	assets, err := MockPipeline{}.Discover(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 0 {
		t.Errorf("tanpa seed tidak boleh ada aset, dapat %d", len(assets))
	}
}
