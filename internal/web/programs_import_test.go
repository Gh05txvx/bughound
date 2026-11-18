package web

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/scope"
	"bughound/internal/store"
)

const importHeader = "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission," +
	"availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at\n"

func importRow(id, submit string) string {
	return id + ",URL,,true," + submit + ",,,,critical,,,\n"
}

// textareaValue takes the rendered textarea content, already unescaped.
func textareaValue(t *testing.T, body, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<textarea[^>]*name="` + name + `"[^>]*>(.*?)</textarea>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("textarea %q not on the page", name)
	}
	return strings.TrimSpace(html.UnescapeString(m[1]))
}

func TestProgramImportFillsFormWithoutSaving(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	data := importHeader + importRow("*.acme.io", "true") + importRow("admin.acme.io", "false")

	rec := do(t, srv, "POST", "/programs/import", url.Values{"name": {"acme"}, "platform_data": {data}})
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if got := textareaValue(t, body, "in_scope"); got != "*.acme.io" {
		t.Errorf("in_scope = %q", got)
	}
	if got := textareaValue(t, body, "out_scope"); got != "admin.acme.io" {
		t.Errorf("out_scope = %q", got)
	}
	if !strings.Contains(body, "Not saved yet") {
		t.Error("the page must state the import result is not saved")
	}

	// The import does NOT save: the new scope takes effect only through the ordinary save path.
	if _, err := st.GetProgram(ctx, "acme"); err != store.ErrNotFound {
		t.Fatalf("the import must not save the program, got %v", err)
	}
	rec = do(t, srv, "POST", "/programs", url.Values{
		"name": {"acme"}, "in_scope": {textareaValue(t, body, "in_scope")}, "out_scope": {textareaValue(t, body, "out_scope")},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d, want 303", rec.Code)
	}
	if p, err := st.GetProgram(ctx, "acme"); err != nil || len(p.InScope) != 1 || len(p.OutScope) != 1 {
		t.Fatalf("the stored program is wrong: %+v (%v)", p, err)
	}
}

func TestProgramImportHeldUntilExclusionsAcknowledged(t *testing.T) {
	srv, _ := newTestServer(t)
	data := importHeader + importRow("app.acme.io", "true") + importRow("support.acme.*", "false")
	res, err := scope.ImportPlatform(data)
	if err != nil {
		t.Fatal(err)
	}
	post := func(raw, ack string) string {
		form := url.Values{"name": {"acme"}, "platform_data": {raw}}
		if ack != "" {
			form.Set("ack_unresolved", ack)
		}
		return do(t, srv, "POST", "/programs/import", form).Body.String()
	}
	assertHeld := func(body, why string) {
		t.Helper()
		if !strings.Contains(body, "Import held") || !strings.Contains(body, "support.acme.*") {
			t.Errorf("%s: the import must be held and show its exclusion", why)
		}
		if got := textareaValue(t, body, "in_scope"); got != "" {
			t.Errorf("%s: the form must not be filled, in_scope = %q", why, got)
		}
	}

	body := post(data, "")
	assertHeld(body, "without agreement")
	if got := textareaValue(t, body, "platform_data"); got != strings.TrimSpace(data) {
		t.Error("the pasted data must be kept while held")
	}
	assertHeld(post(data, "not-a-digest"), "wrong digest")

	// The agreement is bound to the content: it does not apply to other data that is also a problem.
	other := data + importRow("legal.acme.*", "false")
	assertHeld(post(other, res.Digest), "digest of other data")

	body = post(data, res.Digest)
	if got := textareaValue(t, body, "in_scope"); got != "app.acme.io" {
		t.Errorf("after agreement in_scope = %q", got)
	}
	if !strings.Contains(body, "support.acme.*") {
		t.Error("an agreed exclusion must still be visible in the report")
	}
}

func TestProgramImportReplacesInScopeAndKeepsExclusions(t *testing.T) {
	srv, _ := newTestServer(t)
	body := do(t, srv, "POST", "/programs/import", url.Values{
		"name":          {"acme"},
		"in_scope":      {"stale.acme.io\napp.acme.io"},
		"out_scope":     {"# hand-written\nmanual.acme.io"},
		"platform_data": {importHeader + importRow("app.acme.io", "true") + importRow("old.acme.io", "false")},
	}).Body.String()

	// An old in-scope entry may be a dropped asset: it must not carry over.
	if got := textareaValue(t, body, "in_scope"); got != "app.acme.io" {
		t.Errorf("in_scope = %q, want the import result only", got)
	}
	if !strings.Contains(body, "stale.acme.io") {
		t.Error("a replaced in-scope entry must be reported")
	}
	// An exclusion the user wrote must not be lost to the import.
	want := "# hand-written\nmanual.acme.io\nold.acme.io"
	if got := strings.ReplaceAll(textareaValue(t, body, "out_scope"), "\r\n", "\n"); got != want {
		t.Errorf("out_scope = %q, want %q", got, want)
	}
}

func TestProgramImportReportsShadowedInScope(t *testing.T) {
	srv, _ := newTestServer(t)
	body := do(t, srv, "POST", "/programs/import", url.Values{
		"name": {"acme"}, "platform_data": {importHeader + importRow("www.acme.io", "true") + importRow("*.acme.io", "false")},
	}).Body.String()
	if !strings.Contains(body, "overridden by an exclusion") || !strings.Contains(body, "denied by *.acme.io") {
		t.Error("an in-scope entry overridden by an exclusion must be reported along with its trigger")
	}
}

func TestProgramImportRejectsBadDataAndKeepsForm(t *testing.T) {
	srv, _ := newTestServer(t)
	for name, raw := range map[string]string{
		"foreign format":  "acme.io\n*.acme.io",
		"too large": importHeader + strings.Repeat(importRow("app.acme.io", "true"), scope.MaxImportBytes/30),
	} {
		body := do(t, srv, "POST", "/programs/import", url.Values{
			"name": {"acme"}, "in_scope": {"keep.acme.io"}, "platform_data": {raw},
		}).Body.String()
		if !strings.Contains(body, "Import failed") {
			t.Errorf("%s: must show an import error", name)
		}
		if got := textareaValue(t, body, "in_scope"); got != "keep.acme.io" {
			t.Errorf("%s: the form content must be intact, in_scope = %q", name, got)
		}
	}
}

// Platform data is written by a third party: it must not execute on the page.
func TestProgramImportEscapesPlatformText(t *testing.T) {
	srv, _ := newTestServer(t)
	body := do(t, srv, "POST", "/programs/import", url.Values{
		"name": {"acme"}, "platform_data": {importHeader + importRow("<script>alert(1)</script>", "false")},
	}).Body.String()
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("the platform text is not escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)") {
		t.Error("the problem asset must still be visible (escaped)")
	}
}

func TestProgramImportRequiresOperator(t *testing.T) {
	srv, _ := newRBACServer(t)
	form := url.Values{"name": {"acme"}, "platform_data": {importHeader + importRow("app.acme.io", "true")}}

	csrf, sess := loginAs(t, srv, "view", "viewpw")
	if rec := authedReq(srv, "POST", "/programs/import", form, csrf, sess); rec.Code != http.StatusForbidden {
		t.Errorf("viewer POST /programs/import = %d, want 403", rec.Code)
	}
	csrf, sess = loginAs(t, srv, "oper", "operpw")
	if rec := authedReq(srv, "POST", "/programs/import", form, csrf, sess); rec.Code != http.StatusOK {
		t.Errorf("operator POST /programs/import = %d, want 200", rec.Code)
	}
}

func TestProgramImportAndSaveAreAudited(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()
	const marker = "SECRET-PROGRAM"
	data := importHeader + "app.acme.io,URL," + marker + ",true,true,,,,critical,,,\n" + importRow("support.acme.*", "false")
	res, err := scope.ImportPlatform(data)
	if err != nil {
		t.Fatal(err)
	}

	do(t, srv, "POST", "/programs/import", url.Values{"name": {"acme"}, "platform_data": {data}})
	do(t, srv, "POST", "/programs/import", url.Values{"name": {"acme"}, "platform_data": {data}, "ack_unresolved": {res.Digest}})
	do(t, srv, "POST", "/programs/import", url.Values{"name": {"acme"}, "platform_data": {"garbage"}})
	do(t, srv, "POST", "/programs", url.Values{"name": {"acme"}, "in_scope": {"app.acme.io"}})

	imports, err := srv.audit.List(ctx, audit.Filter{Kind: "program.import"})
	if err != nil {
		t.Fatal(err)
	}
	if len(imports) != 3 {
		t.Fatalf("event program.import = %d, want 3", len(imports))
	}
	allowed := 0
	for _, e := range imports {
		if e.Allowed {
			allowed++
			if !strings.Contains(e.Message, res.Digest) {
				t.Errorf("the success event must carry the data digest: %q", e.Message)
			}
		}
		if strings.Contains(e.Message+e.Reason, marker) {
			t.Error("the platform data content must not enter the audit")
		}
	}
	if allowed != 1 {
		t.Errorf("success events = %d, want 1 (held & failed recorded as Allowed=false)", allowed)
	}
	if saves, _ := srv.audit.List(ctx, audit.Filter{Kind: "program.save"}); len(saves) != 1 {
		t.Errorf("event program.save = %d, want 1", len(saves))
	}
}
