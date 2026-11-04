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

// textareaValue mengambil isi textarea yang dirender, sudah di-unescape.
func textareaValue(t *testing.T, body, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<textarea[^>]*name="` + name + `"[^>]*>(.*?)</textarea>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("textarea %q tak ada di halaman", name)
	}
	return strings.TrimSpace(html.UnescapeString(m[1]))
}

func TestProgramImportFillsFormWithoutSaving(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	data := importHeader + importRow("*.acme.io", "true") + importRow("admin.acme.io", "false")

	rec := do(t, srv, "POST", "/programs/import", url.Values{"name": {"acme"}, "platform_data": {data}})
	if rec.Code != http.StatusOK {
		t.Fatalf("impor = %d, ingin 200", rec.Code)
	}
	body := rec.Body.String()
	if got := textareaValue(t, body, "in_scope"); got != "*.acme.io" {
		t.Errorf("in_scope = %q", got)
	}
	if got := textareaValue(t, body, "out_scope"); got != "admin.acme.io" {
		t.Errorf("out_scope = %q", got)
	}
	if !strings.Contains(body, "Belum disimpan") {
		t.Error("halaman harus menegaskan hasil impor belum tersimpan")
	}

	// Impor TIDAK menyimpan: scope baru berlaku hanya lewat jalur simpan biasa.
	if _, err := st.GetProgram(ctx, "acme"); err != store.ErrNotFound {
		t.Fatalf("impor tak boleh menyimpan program, dapat %v", err)
	}
	rec = do(t, srv, "POST", "/programs", url.Values{
		"name": {"acme"}, "in_scope": {textareaValue(t, body, "in_scope")}, "out_scope": {textareaValue(t, body, "out_scope")},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("simpan = %d, ingin 303", rec.Code)
	}
	if p, err := st.GetProgram(ctx, "acme"); err != nil || len(p.InScope) != 1 || len(p.OutScope) != 1 {
		t.Fatalf("program tersimpan salah: %+v (%v)", p, err)
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
		if !strings.Contains(body, "Impor ditahan") || !strings.Contains(body, "support.acme.*") {
			t.Errorf("%s: impor harus ditahan dan menampilkan eksklusinya", why)
		}
		if got := textareaValue(t, body, "in_scope"); got != "" {
			t.Errorf("%s: form tak boleh terisi, in_scope = %q", why, got)
		}
	}

	body := post(data, "")
	assertHeld(body, "tanpa persetujuan")
	if got := textareaValue(t, body, "platform_data"); got != strings.TrimSpace(data) {
		t.Error("data tempelan harus dipertahankan saat ditahan")
	}
	assertHeld(post(data, "bukan-digest"), "digest salah")

	// Persetujuan terikat isi: tak berlaku untuk data lain yang juga bermasalah.
	other := data + importRow("legal.acme.*", "false")
	assertHeld(post(other, res.Digest), "digest milik data lain")

	body = post(data, res.Digest)
	if got := textareaValue(t, body, "in_scope"); got != "app.acme.io" {
		t.Errorf("setelah disetujui in_scope = %q", got)
	}
	if !strings.Contains(body, "support.acme.*") {
		t.Error("eksklusi yang disetujui tetap harus terlihat di laporan")
	}
}

func TestProgramImportReplacesInScopeAndKeepsExclusions(t *testing.T) {
	srv, _ := newTestServer(t)
	body := do(t, srv, "POST", "/programs/import", url.Values{
		"name":          {"acme"},
		"in_scope":      {"stale.acme.io\napp.acme.io"},
		"out_scope":     {"# ditulis tangan\nmanual.acme.io"},
		"platform_data": {importHeader + importRow("app.acme.io", "true") + importRow("old.acme.io", "false")},
	}).Body.String()

	// Entri in-scope lama bisa jadi aset yang sudah dicabut: tak boleh terbawa.
	if got := textareaValue(t, body, "in_scope"); got != "app.acme.io" {
		t.Errorf("in_scope = %q, ingin hanya hasil impor", got)
	}
	if !strings.Contains(body, "stale.acme.io") {
		t.Error("entri in-scope yang digantikan harus dilaporkan")
	}
	// Eksklusi yang ditulis pengguna tak boleh hilang karena impor.
	want := "# ditulis tangan\nmanual.acme.io\nold.acme.io"
	if got := strings.ReplaceAll(textareaValue(t, body, "out_scope"), "\r\n", "\n"); got != want {
		t.Errorf("out_scope = %q, ingin %q", got, want)
	}
}

func TestProgramImportReportsShadowedInScope(t *testing.T) {
	srv, _ := newTestServer(t)
	body := do(t, srv, "POST", "/programs/import", url.Values{
		"name": {"acme"}, "platform_data": {importHeader + importRow("www.acme.io", "true") + importRow("*.acme.io", "false")},
	}).Body.String()
	if !strings.Contains(body, "tertimpa eksklusi") || !strings.Contains(body, "ditolak oleh *.acme.io") {
		t.Error("in-scope yang tertimpa eksklusi harus dilaporkan beserta pemicunya")
	}
}

func TestProgramImportRejectsBadDataAndKeepsForm(t *testing.T) {
	srv, _ := newTestServer(t)
	for name, raw := range map[string]string{
		"format asing":  "acme.io\n*.acme.io",
		"terlalu besar": importHeader + strings.Repeat(importRow("app.acme.io", "true"), scope.MaxImportBytes/30),
	} {
		body := do(t, srv, "POST", "/programs/import", url.Values{
			"name": {"acme"}, "in_scope": {"keep.acme.io"}, "platform_data": {raw},
		}).Body.String()
		if !strings.Contains(body, "Impor gagal") {
			t.Errorf("%s: harus menampilkan galat impor", name)
		}
		if got := textareaValue(t, body, "in_scope"); got != "keep.acme.io" {
			t.Errorf("%s: isi form harus utuh, in_scope = %q", name, got)
		}
	}
}

// Data platform ditulis pihak ketiga: tak boleh dieksekusi di halaman.
func TestProgramImportEscapesPlatformText(t *testing.T) {
	srv, _ := newTestServer(t)
	body := do(t, srv, "POST", "/programs/import", url.Values{
		"name": {"acme"}, "platform_data": {importHeader + importRow("<script>alert(1)</script>", "false")},
	}).Body.String()
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("teks platform tak ter-escape")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)") {
		t.Error("aset bermasalah harus tetap terlihat (ter-escape)")
	}
}

func TestProgramImportRequiresOperator(t *testing.T) {
	srv, _ := newRBACServer(t)
	form := url.Values{"name": {"acme"}, "platform_data": {importHeader + importRow("app.acme.io", "true")}}

	csrf, sess := loginAs(t, srv, "view", "viewpw")
	if rec := authedReq(srv, "POST", "/programs/import", form, csrf, sess); rec.Code != http.StatusForbidden {
		t.Errorf("viewer POST /programs/import = %d, ingin 403", rec.Code)
	}
	csrf, sess = loginAs(t, srv, "oper", "operpw")
	if rec := authedReq(srv, "POST", "/programs/import", form, csrf, sess); rec.Code != http.StatusOK {
		t.Errorf("operator POST /programs/import = %d, ingin 200", rec.Code)
	}
}

func TestProgramImportAndSaveAreAudited(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()
	const marker = "RAHASIA-PROGRAM"
	data := importHeader + "app.acme.io,URL," + marker + ",true,true,,,,critical,,,\n" + importRow("support.acme.*", "false")
	res, err := scope.ImportPlatform(data)
	if err != nil {
		t.Fatal(err)
	}

	do(t, srv, "POST", "/programs/import", url.Values{"name": {"acme"}, "platform_data": {data}})
	do(t, srv, "POST", "/programs/import", url.Values{"name": {"acme"}, "platform_data": {data}, "ack_unresolved": {res.Digest}})
	do(t, srv, "POST", "/programs/import", url.Values{"name": {"acme"}, "platform_data": {"sampah"}})
	do(t, srv, "POST", "/programs", url.Values{"name": {"acme"}, "in_scope": {"app.acme.io"}})

	imports, err := srv.audit.List(ctx, audit.Filter{Kind: "program.import"})
	if err != nil {
		t.Fatal(err)
	}
	if len(imports) != 3 {
		t.Fatalf("event program.import = %d, ingin 3", len(imports))
	}
	allowed := 0
	for _, e := range imports {
		if e.Allowed {
			allowed++
			if !strings.Contains(e.Message, res.Digest) {
				t.Errorf("event sukses harus memuat digest data: %q", e.Message)
			}
		}
		if strings.Contains(e.Message+e.Reason, marker) {
			t.Error("isi data platform tak boleh masuk audit")
		}
	}
	if allowed != 1 {
		t.Errorf("event sukses = %d, ingin 1 (tahan & gagal tercatat Allowed=false)", allowed)
	}
	if saves, _ := srv.audit.List(ctx, audit.Filter{Kind: "program.save"}); len(saves) != 1 {
		t.Errorf("event program.save = %d, ingin 1", len(saves))
	}
}
