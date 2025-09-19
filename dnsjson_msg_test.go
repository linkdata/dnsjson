package dnsjson

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/miekg/dns"
)

const fallbackType = 65280

func TestMsgJSONRoundTrip(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
