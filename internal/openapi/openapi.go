// Package openapi parses an OpenAPI 3 / Swagger 2 spec (JSON or YAML) into a
// list of absolute endpoint URLs. It backs spec-directed scans: each endpoint
// becomes a target that still passes the scope guard before it is scanned, so a
// spec only extends the target list and cannot bypass the security boundary.
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

// Endpoints returns the unique absolute endpoint URLs in spec. fallbackBase
// (e.g. the first target) is used when the spec has no absolute server. Path
// params such as {id} are replaced with "1" to make the URL concrete.
func Endpoints(spec []byte, fallbackBase string) ([]string, error) {
	var d doc
	if err := yaml.Unmarshal(spec, &d); err != nil {
		if jerr := json.Unmarshal(spec, &d); jerr != nil {
			return nil, fmt.Errorf("spec does not parse as YAML/JSON: %v", err)
		}
	}
	if len(d.Paths) == 0 {
		return nil, fmt.Errorf("no 'paths' in spec")
	}
	base, err := baseURL(d, fallbackBase)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []string
	for p := range d.Paths {
		if !strings.HasPrefix(p, "/") {
			continue // skip non-path keys (e.g. $ref, parameters)
		}
		u := strings.TrimRight(base, "/") + pathParam.ReplaceAllString(p, "1")
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid path in spec")
	}
	sort.Strings(out)
	return out, nil
}

func baseURL(d doc, fallback string) (string, error) {
	// OpenAPI 3: servers[0].url (absolute, or relative to the fallback).
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
	// Fallback: the user's target.
	if strings.TrimSpace(fallback) != "" {
		return normalize(fallback), nil
	}
	return "", fmt.Errorf("cannot determine the base URL (no servers/host in spec, and the target is empty)")
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
