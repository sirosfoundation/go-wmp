package wmp

import "testing"

func TestNegotiateVersion(t *testing.T) {
	tests := []struct {
		name      string
		offered   string
		supported []string
		want      string
		ok        bool
	}{
		{"exact", "0.1", []string{"0.1"}, "0.1", true},
		{"higher offered selects highest supported", "0.2", []string{"0.1"}, "0.1", true},
		{"picks highest not above offered", "0.2", []string{"0.1", "0.2", "0.3"}, "0.2", true},
		{"order independent", "0.3", []string{"0.3", "0.1", "0.2"}, "0.3", true},
		{"lower offered than all supported", "0.1", []string{"0.2", "0.3"}, "", false},
		{"different major higher", "1.0", []string{"0.1"}, "", false},
		{"different major lower", "0.9", []string{"1.0"}, "", false},
		{"minor compares numerically", "0.10", []string{"0.9", "0.2"}, "0.9", true},
		{"empty offered", "", []string{"0.1"}, "", false},
		{"no dot", "1", []string{"0.1"}, "", false},
		{"three parts", "0.1.1", []string{"0.1"}, "", false},
		{"sign rejected", "0.+1", []string{"0.1"}, "", false},
		{"negative rejected", "-0.1", []string{"0.1"}, "", false},
		{"space rejected", "0. 1", []string{"0.1"}, "", false},
		{"huge rejected", "0.99999999999", []string{"0.1"}, "", false},
		{"leading zero minor rejected", "0.01", []string{"0.1"}, "", false},
		{"leading zero major rejected", "00.1", []string{"0.1"}, "", false},
		{"zero minor accepted", "0.0", []string{"0.0"}, "0.0", true},
		{"junk supported ignored", "0.2", []string{"x", "0.1"}, "0.1", true},
		{"nothing supported", "0.1", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NegotiateVersion(tt.offered, tt.supported)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("NegotiateVersion(%q, %v) = %q, %v; want %q, %v", tt.offered, tt.supported, got, ok, tt.want, tt.ok)
			}
		})
	}
}
