package pipeline

import "testing"

func TestExtractServiceHost(t *testing.T) {
	got := extractServiceHost("api.example.com:8443", "example.com")
	if got != "api.example.com" {
		t.Fatalf("extractServiceHost() = %q", got)
	}
}

func TestParseHTTPXServiceRow(t *testing.T) {
	raw := `{"input":"api.example.com:8443","url":"https://api.example.com:8443/health","status-code":200,"web-server":"nginx","technologies":["next.js"],"scheme":"https"}`
	row, ok := parseHTTPXServiceRow(raw, "example.com")
	if !ok {
		t.Fatalf("parseHTTPXServiceRow() ok = false")
	}
	if row.Host != "api.example.com" || row.Port != 8443 || row.StatusCode != 200 {
		t.Fatalf("parseHTTPXServiceRow() = %#v", row)
	}
	if row.WebServer != "nginx" || len(row.Technologies) != 1 || row.Technologies[0] != "next.js" {
		t.Fatalf("parseHTTPXServiceRow() metadata = %#v", row)
	}
}
