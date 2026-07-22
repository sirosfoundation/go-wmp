package ws

import (
	"net/http"
	"testing"
)

func TestParseAndValidateURL(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		allowInsecure bool
		wantErr       bool
		wantScheme    string
	}{
		{"wss secure", "wss://example.com/ws", false, false, "wss"},
		{"https secure", "https://example.com/ws", false, false, "https"},
		{"ws blocked by default", "ws://example.com/ws", false, true, ""},
		{"http blocked by default", "http://example.com/ws", false, true, ""},
		{"ws allowed with flag", "ws://example.com/ws", true, false, "ws"},
		{"http allowed with flag", "http://example.com/ws", true, false, "http"},
		{"invalid scheme", "ftp://example.com/ws", false, true, ""},
		{"missing scheme", "example.com/ws", false, true, ""},
		{"invalid URL", "://bad", false, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAndValidateURL(tt.raw, tt.allowInsecure)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAndValidateURL(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.Scheme != tt.wantScheme {
				t.Fatalf("scheme = %q, want %q", got.Scheme, tt.wantScheme)
			}
		})
	}
}

func TestCheckSameOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{"empty origin", "", "example.com", true},
		{"same host", "https://example.com", "example.com", true},
		{"different host", "https://other.example.com", "example.com", false},
		{"case insensitive", "https://EXAMPLE.COM", "example.com", true},
		{"invalid origin URL", "://bad", "example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Host: tt.host}
			if tt.origin != "" {
				r.Header = http.Header{"Origin": []string{tt.origin}}
			}
			if got := checkSameOrigin(r); got != tt.want {
				t.Fatalf("checkSameOrigin(%q, %q) = %v, want %v", tt.origin, tt.host, got, tt.want)
			}
		})
	}
}
