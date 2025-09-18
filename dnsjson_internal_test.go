package dnsjson

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestStringToType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    uint16
		wantErr bool
	}{
		{name: "known mnemonic", input: "A", want: dns.TypeA},
		{name: "numeric string", input: "15", want: dns.TypeMX},
		{name: "unknown", input: "definitely-unknown", wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := stringToType(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("stringToType(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestGetStringSlice(t *testing.T) {
	t.Parallel()
	m := map[string]any{"txt": []any{"chunk1", "chunk2"}}
	got, err := getStringSlice(m, "txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"chunk1", "chunk2"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("getStringSlice mismatch at %d: got %q want %q", i, got[i], want[i])
		}
	}

	_, err = getStringSlice(map[string]any{"txt": "not-a-slice"}, "txt")
	if err == nil {
		t.Fatal("expected error for non-slice input")
	}

	_, err = getStringSlice(map[string]any{"txt": []any{"ok", 123}}, "txt")
	if err == nil {
		t.Fatal("expected error for mixed slice")
	}
}

func TestRRFromJSONFallback(t *testing.T) {
	t.Parallel()
	rr, err := rrFromJSON(RRJSON{
		Name:  "fallback.example.",
		Type:  "99",
		Class: "IN",
		TTL:   123,
		Data: map[string]any{
			"raw": "fallback.example. 0 IN TYPE99 \\# 0",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr == nil {
		t.Fatalf("expected rr, got nil")
	}
	hdr := rr.Header()
	if hdr.Name != "fallback.example." {
		t.Fatalf("unexpected name: %q", hdr.Name)
	}
	if hdr.Ttl != 123 {
		t.Fatalf("ttl not restored from JSON header: got %d", hdr.Ttl)
	}
	if hdr.Class != dns.ClassINET {
		t.Fatalf("unexpected class: %d", hdr.Class)
	}
	if hdr.Rrtype != 99 {
		t.Fatalf("unexpected type: %d", hdr.Rrtype)
	}
}

func TestRRsFromJSONAggregatesErrors(t *testing.T) {
	t.Parallel()
	valid := RRJSON{
		Name:  "valid.example.",
		Type:  "A",
		Class: "IN",
		TTL:   60,
		Data:  map[string]any{"a": "192.0.2.1"},
	}
	invalid := RRJSON{
		Name:  "invalid.example.",
		Type:  "A",
		Class: "IN",
		TTL:   60,
		Data:  map[string]any{"a": "not-an-ip"},
	}

	got, err := rrsFromJSON([]RRJSON{valid, invalid})
	if err == nil {
		t.Fatal("expected aggregated error")
	}
	if !strings.Contains(err.Error(), "ParseAddr") {
		t.Fatalf("unexpected error contents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one successful RR, got %d", len(got))
	}
	if got[0].Header().Name != "valid.example." {
		t.Fatalf("unexpected RR in output: %v", got[0])
	}
}
