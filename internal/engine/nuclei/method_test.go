package nuclei

import "testing"

func TestMethodFromRequest(t *testing.T) {
	cases := map[string]string{
		"POST /rest/products/search?q=a HTTP/1.1\r\nHost: t": "POST",
		"GET /a?b=1 HTTP/1.1":                                "GET",
		"put /x HTTP/1.1":                                    "PUT", // uppercased
		"":                                                   "",
		"garbage":                                            "", // only one field
		"FOO /x HTTP/1.1":                                    "", // unknown method
	}
	for req, want := range cases {
		if got := methodFromRequest(req); got != want {
			t.Errorf("methodFromRequest(%q) = %q, want %q", req, got, want)
		}
	}
}
