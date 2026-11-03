package nuclei

import "testing"

func TestMethodFromRequest(t *testing.T) {
	cases := map[string]string{
		"POST /rest/products/search?q=a HTTP/1.1\r\nHost: t": "POST",
		"GET /a?b=1 HTTP/1.1":                                "GET",
		"put /x HTTP/1.1":                                    "PUT", // di-uppercase
		"":                                                   "",
		"garbage":                                            "", // hanya satu field
		"FOO /x HTTP/1.1":                                    "", // method tak dikenal
	}
	for req, want := range cases {
		if got := methodFromRequest(req); got != want {
			t.Errorf("methodFromRequest(%q) = %q, mau %q", req, got, want)
		}
	}
}
