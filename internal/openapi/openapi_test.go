package openapi

import (
	"sort"
	"strings"
	"testing"
)

func joined(s []string) string { sort.Strings(s); return strings.Join(s, ",") }

func TestEndpointsOpenAPI3Absolute(t *testing.T) {
	spec := []byte(`{"openapi":"3.0.0","servers":[{"url":"https://api.demo.test/v1"}],"paths":{"/users":{"get":{}},"/orders/{id}":{"get":{}}}}`)
	got, err := Endpoints(spec, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://api.demo.test/v1/orders/1", "https://api.demo.test/v1/users"}
	if joined(got) != joined(want) {
		t.Errorf("endpoints = %v; want %v", got, want)
	}
}

func TestEndpointsOpenAPI3RelativeServerWithFallback(t *testing.T) {
	spec := []byte(`{"openapi":"3.0.0","servers":[{"url":"/api"}],"paths":{"/ping":{"get":{}}}}`)
	got, err := Endpoints(spec, "demo.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "https://demo.test/api/ping" {
		t.Errorf("relative server + fallback is wrong: %v", got)
	}
}

func TestEndpointsSwagger2PrefersHTTPS(t *testing.T) {
	spec := []byte(`{"swagger":"2.0","host":"api.demo.test","basePath":"/v2","schemes":["http","https"],"paths":{"/a":{"get":{}}}}`)
	got, err := Endpoints(spec, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "https://api.demo.test/v2/a" {
		t.Errorf("swagger2 is wrong (must pick https): %v", got)
	}
}

func TestEndpointsYAML(t *testing.T) {
	spec := []byte("openapi: 3.0.0\nservers:\n  - url: https://y.demo.test\npaths:\n  /x:\n    get: {}\n")
	got, err := Endpoints(spec, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "https://y.demo.test/x" {
		t.Errorf("yaml parse is wrong: %v", got)
	}
}

func TestEndpointsFallbackNoServer(t *testing.T) {
	got, err := Endpoints([]byte(`{"openapi":"3.0.0","paths":{"/p":{"get":{}}}}`), "https://t.demo.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "https://t.demo.test/p" {
		t.Errorf("fallback base is wrong: %v", got)
	}
}

func TestEndpointsErrors(t *testing.T) {
	if _, err := Endpoints([]byte(`{"openapi":"3.0.0","paths":{}}`), "x"); err == nil {
		t.Error("a spec without paths must error")
	}
	if _, err := Endpoints([]byte(`{"openapi":"3.0.0","paths":{"/p":{"get":{}}}}`), ""); err == nil {
		t.Error("no server and no fallback must error")
	}
}
