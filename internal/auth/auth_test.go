package auth

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := HashPassword("blue-elephant-77")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(h, "blue-elephant-77") {
		t.Error("the correct password must verify")
	}
	if VerifyPassword(h, "blue-elephant-78") {
		t.Error("a wrong password must not verify")
	}
}

func TestHashIsSaltedAndOpaque(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Error("two hashes of the same password must differ (random salt)")
	}
	// The raw password must not appear in the hash.
	if a == "same" || b == "same" {
		t.Error("the hash must not contain the raw password")
	}
}

func TestHashEmptyRejected(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Error("an empty password must be rejected")
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	for _, h := range []string{"", "plaintext", "pbkdf2_sha256$x$y$z", "md5$1$aa$bb", "pbkdf2_sha256$1$!!$!!"} {
		if VerifyPassword(h, "anything") {
			t.Errorf("corrupt hash %q must not verify", h)
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
			t.Errorf("%s CanRead=%v, want %v", c.role, CanRead(c.role), c.read)
		}
		if CanWrite(c.role) != c.write {
			t.Errorf("%s CanWrite=%v, want %v", c.role, CanWrite(c.role), c.write)
		}
		if CanAdmin(c.role) != c.adminPerm {
			t.Errorf("%s CanAdmin=%v, want %v", c.role, CanAdmin(c.role), c.adminPerm)
		}
	}
}

func TestRoleValid(t *testing.T) {
	for _, r := range Roles() {
		if !r.Valid() {
			t.Errorf("%s must be valid", r)
		}
	}
	if Role("").Valid() || Role("root").Valid() {
		t.Error("an empty or unknown role must not be valid")
	}
}
