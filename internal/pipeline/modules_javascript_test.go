package pipeline

import "testing"

func TestCollectJSURLs(t *testing.T) {
	rows := []SurfaceRow{
		{URL: "https://app.example.com/app.js", Path: "/app.js"},
		{URL: "https://app.example.com/app.js", Path: "/app.js"},
		{URL: "https://app.example.com/main.css", Path: "/main.css"},
	}
	got := collectJSURLs(rows, 10)
	if len(got) != 1 || got[0] != "https://app.example.com/app.js" {
		t.Fatalf("collectJSURLs() = %#v", got)
	}
}

func TestExtractJSRelativeURLs(t *testing.T) {
	blob := `const a="/api/v1/users"; const b="/auth/login";`
	got := extractJSRelativeURLs("https://app.example.com/static/app.js", blob)
	if len(got) != 2 {
		t.Fatalf("extractJSRelativeURLs() len = %d, want 2", len(got))
	}
	if got[0] != "https://app.example.com/api/v1/users" && got[1] != "https://app.example.com/api/v1/users" {
		t.Fatalf("extractJSRelativeURLs() missing api path: %#v", got)
	}
}

func TestExtractJSRelativeURLsLooseAndProtocolRelative(t *testing.T) {
	blob := `const a="api/v2/orders"; const b="//cdn.example.com/app.js"; const c="../graphql";`
	got := extractJSRelativeURLs("https://app.example.com/static/js/app.js", normalizeJSBlob(blob))
	want := map[string]struct{}{
		"https://app.example.com/api/v2/orders":  {},
		"https://cdn.example.com/app.js":         {},
		"https://app.example.com/static/graphql": {},
	}
	for expected := range want {
		found := false
		for _, raw := range got {
			if raw == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("extractJSRelativeURLs() missing %s in %#v", expected, got)
		}
	}
}

func TestExtractJSHosts(t *testing.T) {
	blob := `window.api="https://api.example.com/v1"; window.cdn="https://cdn.other.com/x.js";`
	got := extractJSHosts(blob, "example.com")
	if len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("extractJSHosts() = %#v", got)
	}
}

func TestFFUFRowsFilter(t *testing.T) {
	rows := []ContentRow{
		{URL: "https://app.example.com/admin", Source: "ffuf"},
		{URL: "https://app.example.com/login", Source: "surface"},
	}
	got := ffufRows(rows)
	if len(got) != 1 || got[0].Source != "ffuf" {
		t.Fatalf("ffufRows() = %#v", got)
	}
}

func TestNormalizeJSBlob(t *testing.T) {
	got := normalizeJSBlob(`{"a":"\/api\/v1","b":"\u002fauth","c":"\x2fgraphql"}`)
	if got != `{"a":"/api/v1","b":"/auth","c":"/graphql"}` {
		t.Fatalf("normalizeJSBlob() = %q", got)
	}
}
