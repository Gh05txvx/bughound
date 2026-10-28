package auth

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := HashPassword("gajah-biru-77")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(h, "gajah-biru-77") {
		t.Error("kata sandi benar harus terverifikasi")
	}
	if VerifyPassword(h, "gajah-biru-78") {
		t.Error("kata sandi salah tak boleh terverifikasi")
	}
}

func TestHashIsSaltedAndOpaque(t *testing.T) {
	a, _ := HashPassword("sama")
	b, _ := HashPassword("sama")
	if a == b {
		t.Error("dua hash dari kata sandi sama harus berbeda (salt acak)")
	}
	// Kata sandi mentah tak boleh muncul di hash.
	if a == "sama" || b == "sama" {
		t.Error("hash tak boleh berisi kata sandi mentah")
	}
}

func TestHashEmptyRejected(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Error("kata sandi kosong harus ditolak")
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	for _, h := range []string{"", "plaintext", "pbkdf2_sha256$x$y$z", "md5$1$aa$bb", "pbkdf2_sha256$1$!!$!!"} {
		if VerifyPassword(h, "apa pun") {
			t.Errorf("hash rusak %q tak boleh lolos verifikasi", h)
		}
	}
}

func TestRolePermissions(t *testing.T) {
	cases := []struct {
		role                   Role
		read, write, adminPerm bool
	}{
		{RoleViewer, true, false, false},
		{RoleOperator, true, true, false},
		{RoleAdmin, true, true, true},
		{Role("bogus"), false, false, false},
	}
	for _, c := range cases {
		if CanRead(c.role) != c.read {
			t.Errorf("%s CanRead=%v, ingin %v", c.role, CanRead(c.role), c.read)
		}
		if CanWrite(c.role) != c.write {
			t.Errorf("%s CanWrite=%v, ingin %v", c.role, CanWrite(c.role), c.write)
		}
		if CanAdmin(c.role) != c.adminPerm {
			t.Errorf("%s CanAdmin=%v, ingin %v", c.role, CanAdmin(c.role), c.adminPerm)
		}
	}
}

func TestRoleValid(t *testing.T) {
	for _, r := range Roles() {
		if !r.Valid() {
			t.Errorf("%s harus valid", r)
		}
	}
	if Role("").Valid() || Role("root").Valid() {
		t.Error("peran kosong/tak dikenal tak boleh valid")
	}
}
