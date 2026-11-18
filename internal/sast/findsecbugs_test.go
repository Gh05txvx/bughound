package sast

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"bughound/internal/finding"
)

const spotbugsSARIF = `{
  "runs": [{
    "tool": {"driver": {"name": "SpotBugs", "rules": [
      {"id": "SQL_INJECTION_JDBC", "name": "SQL_INJECTION_JDBC",
       "shortDescription": {"text": "Potential SQL Injection"},
       "helpUri": "https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC",
       "defaultConfiguration": {"level": "error"},
       "properties": {"tags": ["security"]}}
    ]}},
    "results": [
      {"ruleId": "SQL_INJECTION_JDBC", "level": "error",
       "message": {"text": "This use of java/sql/Statement may be SQL injection."},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "com/example/Dao.java"}, "region": {"startLine": 88}}}]}
    ]
  }]
}`

func TestParseFindSecBugs(t *testing.T) {
	fs, err := parseFindSecBugs([]byte(spotbugsSARIF))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1, got %d", len(fs))
	}
	f := fs[0]
	if f.Type != "SQL_INJECTION_JDBC" {
		t.Errorf("type: %s", f.Type)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity: want high, got %s", f.Severity)
	}
	if f.Location.URL != "com/example/Dao.java:88" {
		t.Errorf("location: %s", f.Location.URL)
	}
	if f.SourceEngine != "findsecbugs" {
		t.Errorf("engine: %s", f.SourceEngine)
	}
	for _, want := range []string{"java", "sast", "findsecbugs"} {
		if !hasTag(f.Tags, want) {
			t.Errorf("tag %q is missing from %v", want, f.Tags)
		}
	}
}

func TestDiscoverJVMTargets(t *testing.T) {
	root := t.TempDir()
	// Create: sub/app.jar, classes/com/Foo.class + classes/com/Bar.class (one dir),
	// src/Main.java (ignored).
	must := func(p string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(root, "sub", "app.jar"))
	must(filepath.Join(root, "classes", "com", "Foo.class"))
	must(filepath.Join(root, "classes", "com", "Bar.class"))
	must(filepath.Join(root, "src", "Main.java"))

	got := discoverJVMTargets(root, 200)
	wantJar := filepath.Join(root, "sub", "app.jar")
	wantClassDir := filepath.Join(root, "classes", "com")
	if !slices.Contains(got, wantJar) {
		t.Errorf("jar not found: %v", got)
	}
	if !slices.Contains(got, wantClassDir) {
		t.Errorf("class dir not found: %v", got)
	}
	// The class dir appears only once even with 2 .class files.
	n := 0
	for _, p := range got {
		if p == wantClassDir {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the class dir must be deduped, it appears %d times", n)
	}
	// .java does not count as a target.
	for _, p := range got {
		if filepath.Ext(p) == ".java" {
			t.Errorf(".java must not become a target: %s", p)
		}
	}
}

func TestDiscoverJVMTargetsEmpty(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "readme.txt"), []byte("x"), 0o644)
	if got := discoverJVMTargets(root, 200); len(got) != 0 {
		t.Errorf("without bytecode there must be 0 targets, got %v", got)
	}
}

func TestFindSecBugsRegistered(t *testing.T) {
	if _, ok := Lookup("findsecbugs"); !ok {
		t.Error("the findsecbugs adapter is not registered")
	}
}
