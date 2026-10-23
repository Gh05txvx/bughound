// Package openapi mem-parse spec OpenAPI 3 / Swagger 2 (JSON atau YAML) menjadi
// daftar URL endpoint absolut. Dipakai untuk scan ter-arah spec: tiap endpoint
// menjadi target yang TETAP melewati scope guard sebelum di-scan — jadi spec
// hanya memperluas daftar target, tidak memintas batas keamanan.
package openapi

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type doc struct {
	Servers []struct {
		URL string `yaml:"url" json:"url"`
	} `yaml:"servers" json:"servers"`
	Host     string         `yaml:"host" json:"host"`         // Swagger 2
	BasePath string         `yaml:"basePath" json:"basePath"` // Swagger 2
	Schemes  []string       `yaml:"schemes" json:"schemes"`   // Swagger 2
	Paths    map[string]any `yaml:"paths" json:"paths"`
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// Endpoints mengembalikan URL endpoint absolut unik dari spec. fallbackBase
// (mis. target pertama) dipakai bila spec tak punya server absolut. Param path
// {id} diganti "1" agar URL konkret.
func Endpoints(spec []byte, fallbackBase string) ([]string, error) {
	var d doc
	if err := yaml.Unmarshal(spec, &d); err != nil {
		if jerr := json.Unmarshal(spec, &d); jerr != nil {
			return nil, fmt.Errorf("spec tak terurai sebagai YAML/JSON: %v", err)
		}
	}
	if len(d.Paths) == 0 {
		return nil, fmt.Errorf("tak ada 'paths' di spec")
	}
	base, err := baseURL(d, fallbackBase)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []string
	for p := range d.Paths {
		if !strings.HasPrefix(p, "/") {
			continue // lewati kunci non-path (mis. $ref, parameters)
		}
		u := strings.TrimRight(base, "/") + pathParam.ReplaceAllString(p, "1")
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tak ada path valid di spec")
	}
	sort.Strings(out)
	return out, nil
}

func baseURL(d doc, fallback string) (string, error) {
	// OpenAPI 3: servers[0].url (absolut atau relatif terhadap fallback).
	if len(d.Servers) > 0 && strings.TrimSpace(d.Servers[0].URL) != "" {
		s := strings.TrimSpace(d.Servers[0].URL)
		if isAbs(s) {
			return s, nil
		}
		if fallback != "" {
			return strings.TrimRight(normalize(fallback), "/") + ensureSlash(s), nil
		}
	}
	// Swagger 2: scheme://host/basePath.
	if strings.TrimSpace(d.Host) != "" {
		scheme := "https"
		if len(d.Schemes) > 0 {
			scheme = d.Schemes[0]
			for _, s := range d.Schemes {
				if s == "https" {
					scheme = "https"
					break
				}
			}
		}
		return scheme + "://" + strings.TrimRight(d.Host+d.BasePath, "/"), nil
	}
	// Fallback: target pengguna.
	if strings.TrimSpace(fallback) != "" {
		return normalize(fallback), nil
	}
	return "", fmt.Errorf("tak bisa menentukan base URL (tak ada servers/host di spec, dan target kosong)")
}

func isAbs(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func normalize(b string) string {
	b = strings.TrimSpace(b)
	if !isAbs(b) {
		b = "https://" + b
	}
	return strings.TrimRight(b, "/")
}

func ensureSlash(p string) string {
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}
