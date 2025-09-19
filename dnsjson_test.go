package dnsjson

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestStringToType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint16
		wantErr bool
	}{
		{name: "known mnemonic", input: "A", want: dns.TypeA},
		{name: "case insensitive", input: "a", want: dns.TypeA},
		{name: "numeric string", input: "15", want: dns.TypeMX},
		{name: "unknown", input: "definitely-unknown", wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

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

func TestClassToString(t *testing.T) {

	tests := []struct {
		name string
		in   uint16
		want string
	}{
		{name: "known class", in: dns.ClassINET, want: "IN"},
		{name: "unknown class", in: 9999, want: "9999"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			if got := classToString(tc.in); got != tc.want {
				t.Fatalf("classToString(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTypeToString(t *testing.T) {
	tests := []struct {
		name string
		in   uint16
		want string
	}{
		{name: "known type", in: dns.TypeAAAA, want: "AAAA"},
		{name: "unknown type", in: 9999, want: "9999"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			if got := typeToString(tc.in); got != tc.want {
				t.Fatalf("typeToString(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStringToClass(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint16
		wantErr bool
	}{
		{name: "known mnemonic", input: "IN", want: dns.ClassINET},
		{name: "case insensitive", input: "in", want: dns.ClassINET},
		{name: "numeric string", input: "254", want: 254},
		{name: "unknown", input: "definitely-unknown", wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			got, err := stringToClass(tc.input)
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
				t.Fatalf("stringToClass(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestGetUintHelpers(t *testing.T) {
	m := map[string]any{
		"u8":    float64(42),
		"u16":   int(65535),
		"u32n":  json.Number("123456"),
		"u32s":  "789",
		"int64": int64(65535),
	}

	if got := getUint8(m, "u8"); got != 42 {
		t.Fatalf("getUint8 = %d, want 42", got)
	}
	if got := getUint16(m, "u16"); got != 65535 {
		t.Fatalf("getUint16 = %d, want 65535", got)
	}
	if got := getUint32(m, "u32n"); got != 123456 {
		t.Fatalf("getUint32(json.Number) = %d, want 123456", got)
	}
	if got := getUint32(m, "u32s"); got != 789 {
		t.Fatalf("getUint32(string) = %d, want 789", got)
	}
	if got := getUint16(m, "missing"); got != 0 {
		t.Fatalf("getUint16 missing key = %d, want 0", got)
	}
	if got := getUint32(m, "int64"); got != 65535 {
		t.Fatalf("getUint32 = %d, want 65535", got)
	}
}

func TestGetStringSlice(t *testing.T) {
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

func TestGetUint8Slice(t *testing.T) {
	m := map[string]any{
		"algs": []any{float64(1), json.Number("2"), uint8(3)},
	}

	got, err := getUint8Slice(m, "algs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []uint8{1, 2, 3}
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("value mismatch at %d: got %d want %d", i, got[i], want[i])
		}
	}

	if _, err := getUint8Slice(map[string]any{"algs": "not-an-array"}, "algs"); !errors.Is(err, ErrUint8SliceType) {
		t.Fatalf("expected ErrUint8SliceType, got %v", err)
	}

	if _, err := getUint8Slice(map[string]any{"algs": []any{true}}, "algs"); !errors.Is(err, ErrInvalidNumberType) {
		t.Fatalf("expected ErrInvalidNumberType, got %v", err)
	}

	if _, err := getUint8Slice(map[string]any{"algs": []any{float64(-1)}}, "algs"); !errors.Is(err, ErrNegativeValue) {
		t.Fatalf("expected ErrNegativeValue, got %v", err)
	}

	if _, err := getUint8Slice(map[string]any{"algs": []any{float64(300)}}, "algs"); !errors.Is(err, ErrUint8SliceRange) {
		t.Fatalf("expected ErrUint8SliceRange, got %v", err)
	}
}

func TestAnyToUint64(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    uint64
		wantErr error
	}{
		{name: "float", input: float64(42.5), want: 42},
		{name: "negative float", input: float64(-1), wantErr: ErrNegativeValue},
		{name: "json number", input: json.Number("10"), want: 10},
		{name: "json number string", input: json.Number("-11"), wantErr: ErrNegativeValue},
		{name: "string", input: "123", want: 123},
		{name: "int", input: int(1), want: 1},
		{name: "int64", input: int64(1), want: 1},
		{name: "uint8", input: uint8(1), want: 1},
		{name: "uint16", input: uint16(1), want: 1},
		{name: "uint32", input: uint32(1), want: 1},
		{name: "uint64", input: uint64(1), want: 1},
		{name: "negative int", input: int(-5), wantErr: ErrNegativeValue},
		{name: "negative int64", input: int64(-5), wantErr: ErrNegativeValue},
		{name: "invalid type", input: true, wantErr: ErrInvalidNumberType},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := anyToUint64(tc.input)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("anyToUint64(%v) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestGetBool(t *testing.T) {
	m := map[string]any{
		"bool":         true,
		"string":       "true",
		"stringBad":    "nope",
		"floatZero":    float64(0),
		"float":        float64(2),
		"jsonZero":     json.Number("0"),
		"jsonPositive": json.Number("5"),
	}

	tests := []struct {
		name string
		key  string
		want bool
		ok   bool
	}{
		{name: "bool", key: "bool", want: true, ok: true},
		{name: "string", key: "string", want: true, ok: true},
		{name: "string invalid", key: "stringBad", want: false, ok: false},
		{name: "float zero", key: "floatZero", want: false, ok: true},
		{name: "float positive", key: "float", want: true, ok: true},
		{name: "json zero", key: "jsonZero", want: false, ok: true},
		{name: "json positive", key: "jsonPositive", want: true, ok: true},
		{name: "missing", key: "missing", want: false, ok: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, ok := getBool(m, tc.key)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("getBool(%q) = (%v, %v), want (%v, %v)", tc.key, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestRRFromJSONFallback(t *testing.T) {
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

func TestWrapError(t *testing.T) {
	if got := wrapError(ErrInvalidJSON, nil); got != nil {
		t.Fatalf("wrapError should return nil when err nil: got %v", got)
	}

	base := errors.New("boom")
	err := wrapError(ErrInvalidJSON, base)
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("expected errors.Is to match sentinel: %v", err)
	}
	if got := err.Error(); got != "invalid JSON: boom" {
		t.Errorf("%q != %q", got, "invalid JSON: boom")
	}
	if errors.Unwrap(err) != base {
		t.Fatalf("expected unwrap to yield original error, got %v", errors.Unwrap(err))
	}
}

func TestUnknownTypeErrorIs(t *testing.T) {
	_, err := stringToType("definitely-unknown")
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
	if !errors.Is(err, ErrUnknownType) {
		t.Fatalf("expected errors.Is to match ErrUnknownType: %v", err)
	}
	if errors.Is(err, ErrUnknownClass) {
		t.Fatalf("unexpected match against ErrUnknownClass: %v", err)
	}

	var ute *unknownTypeError
	if !errors.As(err, &ute) {
		t.Fatalf("expected unknownTypeError, got %T", err)
	}
	if ute.Error() != "unknown type \"definitely-unknown\"" {
		t.Fatalf("unexpected error string: %q", ute.Error())
	}
}

func TestUnknownClassErrorIs(t *testing.T) {
	_, err := stringToClass("definitely-unknown")
	if err == nil {
		t.Fatal("expected error for unknown class")
	}
	if !errors.Is(err, ErrUnknownClass) {
		t.Fatalf("expected errors.Is to match ErrUnknownClass: %v", err)
	}
	if errors.Is(err, ErrUnknownType) {
		t.Fatalf("unexpected match against ErrUnknownType: %v", err)
	}

	var uce *unknownClassError
	if !errors.As(err, &uce) {
		t.Fatalf("expected unknownClassError, got %T", err)
	}
	if uce.Error() != "unknown class \"definitely-unknown\"" {
		t.Fatalf("unexpected error string: %q", uce.Error())
	}
}

func TestStringSliceErrorIs(t *testing.T) {
	_, err := getStringSlice(map[string]any{"txt": "not-a-slice"}, "txt")
	if err == nil {
		t.Fatal("expected error for invalid string slice")
	}
	if !errors.Is(err, ErrInvalidStringSlice) {
		t.Fatalf("expected errors.Is to match ErrInvalidStringSlice: %v", err)
	}

	var sse *stringSliceError
	if !errors.As(err, &sse) {
		t.Fatalf("expected stringSliceError, got %T", err)
	}
	if sse.Error() != "txt must be array of strings" {
		t.Fatalf("unexpected error string: %q", sse.Error())
	}
}

const fallbackType = 65280

func TestMsgJSONRoundTrip(t *testing.T) {
	fixtures := messageFixtures(t)

	expectedTypes := map[uint16]string{
		dns.TypeA:      "A",
		dns.TypeAAAA:   "AAAA",
		dns.TypeCNAME:  "CNAME",
		dns.TypeNS:     "NS",
		dns.TypePTR:    "PTR",
		dns.TypeTXT:    "TXT",
		dns.TypeMX:     "MX",
		dns.TypeSRV:    "SRV",
		dns.TypeSOA:    "SOA",
		dns.TypeCAA:    "CAA",
		dns.TypeNAPTR:  "NAPTR",
		dns.TypeDS:     "DS",
		dns.TypeDNSKEY: "DNSKEY",
		dns.TypeRRSIG:  "RRSIG",
		dns.TypeTLSA:   "TLSA",
		dns.TypeOPT:    "OPT",
		fallbackType:   "TYPE65280",
	}

	seenTypes := make(map[uint16]bool)

	for name, want := range fixtures {
		want := want
		t.Run(name, func(t *testing.T) {
			t.Helper()

			data, err := json.Marshal((*Msg)(want))
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var got Msg
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal failed: %v\nJSON: %s", err, data)
			}

			wantCopy := want.Copy()
			gotMsg := dns.Msg(got)

			if wantCopy.String() != gotMsg.String() {
				t.Fatalf("round-trip mismatch\nwant: %s\njson: %s\ngot: %s", wantCopy, data, gotMsg.String())
			}
		})

		for _, rr := range want.Answer {
			seenTypes[rr.Header().Rrtype] = true
		}
		for _, rr := range want.Ns {
			seenTypes[rr.Header().Rrtype] = true
		}
		for _, rr := range want.Extra {
			seenTypes[rr.Header().Rrtype] = true
		}
	}

	for typ, label := range expectedTypes {
		if !seenTypes[typ] {
			t.Fatalf("test fixtures missing record for type %s", label)
		}
	}
}

func TestMsgMarshalNil(t *testing.T) {
	var m *Msg
	got, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal nil failed: %v", err)
	}
	if string(got) != "null" {
		t.Fatalf("unexpected JSON for nil Msg: %s", got)
	}
}

func TestMsgUnmarshalNull(t *testing.T) {
	var msg Msg
	if err := json.Unmarshal([]byte("null"), &msg); err != nil {
		t.Fatalf("Unmarshal null failed: %v", err)
	}
	dnsMsg := dns.Msg(msg)
	if dnsMsg.Id != 0 || len(dnsMsg.Question) != 0 || len(dnsMsg.Answer) != 0 || len(dnsMsg.Ns) != 0 || len(dnsMsg.Extra) != 0 {
		t.Fatalf("expected zero-value message after null unmarshal, got %+v", dnsMsg)
	}
}

func messageFixtures(t *testing.T) map[string]*dns.Msg {
	t.Helper()

	const ttl = 600

	header := func(name string, rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
	}

	fallbackRR := mustRR(t, "raw.example. 3600 IN TYPE65280 \\# 4 01020304")
	fallbackRR.Header().Name = "raw.example."
	fallbackRR.Header().Class = dns.ClassINET
	fallbackRR.Header().Rrtype = fallbackType
	fallbackRR.Header().Ttl = 3600

	edns := new(dns.OPT)
	edns.Hdr.Name = "."
	edns.Hdr.Rrtype = dns.TypeOPT
	edns.SetUDPSize(1232)
	edns.SetExtendedRcode(0x5A << 4)
	edns.SetVersion(1)
	edns.SetDo(true)
	edns.SetCo(true)
	edns.SetZ(0x1234)
	edns.Option = append(edns.Option,
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "31323334"},
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 0, Address: net.IPv4(198, 51, 100, 0)},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "00112233445566778899aabbccddeeff"},
		&dns.EDNS0_UL{Code: dns.EDNS0UL, Lease: 3600, KeyLease: 7200},
		&dns.EDNS0_LLQ{Code: dns.EDNS0LLQ, Version: 1, Opcode: 2, Error: 0, Id: 123456789, LeaseLife: 600},
		&dns.EDNS0_DAU{Code: dns.EDNS0DAU, AlgCode: []uint8{8, 13}},
		&dns.EDNS0_DHU{Code: dns.EDNS0DHU, AlgCode: []uint8{1, 2}},
		&dns.EDNS0_N3U{Code: dns.EDNS0N3U, AlgCode: []uint8{1}},
		&dns.EDNS0_EXPIRE{Code: dns.EDNS0EXPIRE, Expire: 86400},
		&dns.EDNS0_LOCAL{Code: dns.EDNS0LOCALSTART + 1, Data: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		&dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: 10},
		&dns.EDNS0_PADDING{Padding: []byte{0x00, 0x01, 0x02, 0x03}},
		&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked, ExtraText: "blocked"},
		&dns.EDNS0_ESU{Code: dns.EDNS0ESU, Uri: "sip:example.com"},
	)

	full := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 4242,
			Response:           true,
			Opcode:             dns.OpcodeUpdate,
			Authoritative:      true,
			Truncated:          true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Zero:               true,
			AuthenticatedData:  true,
			CheckingDisabled:   true,
			Rcode:              dns.RcodeNameError,
		},
		Question: []dns.Question{
			{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			{Name: "aaaa.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassCHAOS},
		},
		Answer: []dns.RR{
			&dns.A{Hdr: header("a.example.", dns.TypeA), A: net.IPv4(192, 0, 2, 1)},
			&dns.AAAA{Hdr: header("aaaa.example.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::1")},
			&dns.CNAME{Hdr: header("alias.example.", dns.TypeCNAME), Target: "target.example."},
			&dns.NS{Hdr: header("example.", dns.TypeNS), Ns: "ns1.example."},
			&dns.PTR{Hdr: header("1.2.0.192.in-addr.arpa.", dns.TypePTR), Ptr: "ptr.example."},
		},
		Ns: []dns.RR{
			&dns.TXT{Hdr: header("txt.example.", dns.TypeTXT), Txt: []string{"chunk1", "chunk2"}},
			&dns.MX{Hdr: header("example.", dns.TypeMX), Preference: 10, Mx: "mail.example."},
			&dns.SRV{Hdr: header("_service._tcp.example.", dns.TypeSRV), Priority: 0, Weight: 5, Port: 443, Target: "srv.example."},
			&dns.SOA{
				Hdr:     header("example.", dns.TypeSOA),
				Ns:      "ns1.example.",
				Mbox:    "hostmaster.example.",
				Serial:  2023120101,
				Refresh: 7200,
				Retry:   900,
				Expire:  1209600,
				Minttl:  3600,
			},
		},
		Extra: []dns.RR{
			&dns.CAA{Hdr: header("example.", dns.TypeCAA), Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
			&dns.NAPTR{
				Hdr:         header("example.", dns.TypeNAPTR),
				Order:       100,
				Preference:  50,
				Flags:       "s",
				Service:     "SIP+D2U",
				Regexp:      "!^.*$!sip:info@example.com!",
				Replacement: "_sip._udp.example.",
			},
			&dns.DS{
				Hdr:        header("example.", dns.TypeDS),
				KeyTag:     12345,
				Algorithm:  8,
				DigestType: 2,
				Digest:     "BEEFCAFE0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
			},
			&dns.DNSKEY{
				Hdr:       header("example.", dns.TypeDNSKEY),
				Flags:     257,
				Protocol:  3,
				Algorithm: 8,
				PublicKey: "AwEAAcR2examplePublicKey==",
			},
			&dns.RRSIG{
				Hdr:         header("example.", dns.TypeRRSIG),
				TypeCovered: dns.TypeA,
				Algorithm:   8,
				Labels:      2,
				OrigTtl:     600,
				Expiration:  1735689600,
				Inception:   1733097600,
				KeyTag:      12345,
				SignerName:  "example.",
				Signature:   "exampleSignatureBase64==",
			},
			&dns.TLSA{
				Hdr:          header("_443._tcp.example.", dns.TypeTLSA),
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  "abcdef1234567890",
			},
			edns,
			fallbackRR,
		},
	}

	minimal := new(dns.Msg)
	minimal.SetQuestion("minimal.example.", dns.TypeTXT)

	return map[string]*dns.Msg{
		"full":    full,
		"minimal": minimal,
	}
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("failed to parse RR %q: %v", s, err)
	}
	return rr
}
