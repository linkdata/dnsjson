// Package dnsjson provides JSON marshalling/unmarshalling helpers for github.com/miekg/dns *dns.Msg
// using an explicit, human-readable JSON schema (no wire-format fields).
//
// Schema overview (stable keys; rdata keys per RR type listed below):
// {
//   "id": 1234,
//   "msgHdr": {"qr":true, "opcode":"QUERY", "aa":false, "tc":false, "rd":true,
//               "ra":true, "z":0, "ad":false, "cd":false, "rcode":"NOERROR"},
//   "question": [{"name":"example.com.", "qtype":"A", "qclass":"IN"}],
//   "answer":  [ RRJSON, ... ],
//   "ns":      [ RRJSON, ... ],
//   "extra":   [ RRJSON, ... ]
// }
//
// RRJSON (common fields) + per-type data (examples):
// {
//   "name":"example.com.", "type":"A", "class":"IN", "ttl":300,
//   "data": { "a":"93.184.216.34" }
// }
// AAAA: {"aaaa":"2001:db8::1"}
// CNAME: {"target":"alias.example."}
// NS: {"ns":"ns1.example."}
// PTR: {"ptr":"host.example."}
// TXT: {"txt":["chunk1","chunk2"]}
// MX: {"preference":10, "mx":"mail.example."}
// SRV: {"priority":0, "weight":5, "port":443, "target":"svc.example."}
// SOA: {"ns":"ns1.", "mbox":"hostmaster.", "serial":1, "refresh":7200, "retry":900, "expire":1209600, "minttl":300}
// CAA: {"flag":0, "tag":"issue", "value":"letsencrypt.org"}
// NAPTR: {"order":100, "preference":50, "flags":"s", "services":"SIP+D2U", "regexp":"", "replacement":"_sip._udp.example."}
// DS: {"key_tag":12345, "algorithm":8, "digest_type":2, "digest":"...hex..."}
// DNSKEY: {"flags":257, "protocol":3, "algorithm":8, "public_key":"base64..."}
// RRSIG: {"type_covered":"A", "algorithm":8, "labels":2, "original_ttl":300,
//         "expiration": 1735689600, "inception": 1733097600, "key_tag":12345,
//         "signer_name":"example.", "signature":"base64..."}
// TLSA: {"usage":3, "selector":1, "matching_type":1, "cert_data":"hex or base64"}
//
// Notes
//  - Type/class use standard mnemonics (e.g., "A", "AAAA", "IN").
//  - Unknown/less-common RR types are round-tripped via a best-effort map in "data"; if a
//    type is not implemented below, Marshal will include {"raw": "<presentation>"} and
//    Unmarshal will parse it using dns.NewRR on a synthesized presentation string.
//  - Times in RRSIG use UNIX seconds per miekg/dns conventions.

package dnsjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type Msg dns.Msg

var _ json.Marshaler = &Msg{}
var _ json.Unmarshaler = &Msg{}

// MessageJSON is the top-level JSON shape for dns.Msg.
type MessageJSON struct {
	ID       uint16     `json:"id"`
	MsgHdr   MsgHdr     `json:"msgHdr"`
	Question []Question `json:"question"`
	Answer   []RRJSON   `json:"answer,omitempty"`
	Ns       []RRJSON   `json:"ns,omitempty"`
	Extra    []RRJSON   `json:"extra,omitempty"`
}

type MsgHdr struct {
	QR     bool   `json:"qr,omitempty"`
	Opcode string `json:"opcode"`
	AA     bool   `json:"aa,omitempty"`
	TC     bool   `json:"tc,omitempty"`
	RD     bool   `json:"rd,omitempty"`
	RA     bool   `json:"ra,omitempty"`
	Z      bool   `json:"z,omitempty"`
	AD     bool   `json:"ad,omitempty"`
	CD     bool   `json:"cd,omitempty"`
	Rcode  string `json:"rcode"`
}

type Question struct {
	Name   string `json:"name"`
	Qtype  string `json:"qtype"`
	Qclass string `json:"qclass"`
}

// RRJSON contains common RR header fields plus a per-type data map.
type RRJSON struct {
	Name  string         `json:"name"`
	Type  string         `json:"type"`
	Class string         `json:"class"`
	TTL   uint32         `json:"ttl"`
	Data  map[string]any `json:"data"`
}

// Marshal converts *dns.Msg -> JSON bytes using the explicit schema.
func (m *Msg) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	j := MessageJSON{
		ID:     m.Id,
		MsgHdr: hdrToJSON(m.MsgHdr),
	}
	// Questions
	for _, q := range m.Question {
		j.Question = append(j.Question, Question{
			Name:   q.Name,
			Qtype:  typeToString(q.Qtype),
			Qclass: classToString(q.Qclass),
		})
	}
	// Sections
	var err error
	if j.Answer, err = rrsToJSON(m.Answer); err != nil {
		return nil, err
	}
	if j.Ns, err = rrsToJSON(m.Ns); err != nil {
		return nil, err
	}
	if j.Extra, err = rrsToJSON(m.Extra); err != nil {
		return nil, err
	}
	return json.Marshal(j)
}

func (msg *Msg) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return errors.New("dnsjson: empty input")
	}
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("dnsjson: invalid JSON: %w", err)
	}
	if string(raw) == "null" {
		return nil
	}
	var j MessageJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return fmt.Errorf("dnsjson: invalid message: %w", err)
	}

	msg.Id = j.ID
	msg.MsgHdr = hdrFromJSON(j.MsgHdr)
	// Questions
	for _, qj := range j.Question {
		qt, err := stringToType(qj.Qtype)
		if err != nil {
			return fmt.Errorf("dnsjson: question qtype: %w", err)
		}
		qc, err := stringToClass(qj.Qclass)
		if err != nil {
			return fmt.Errorf("dnsjson: question qclass: %w", err)
		}
		msg.Question = append(msg.Question, dns.Question{Name: qj.Name, Qtype: qt, Qclass: qc})
	}
	// Sections
	var err error
	if msg.Answer, err = rrsFromJSON(j.Answer); err != nil {
		return fmt.Errorf("answer: %w", err)
	}
	if msg.Ns, err = rrsFromJSON(j.Ns); err != nil {
		return fmt.Errorf("ns: %w", err)
	}
	if msg.Extra, err = rrsFromJSON(j.Extra); err != nil {
		return fmt.Errorf("extra: %w", err)
	}
	return nil
}

// --- helpers ---

func hdrToJSON(h dns.MsgHdr) MsgHdr {
	return MsgHdr{
		QR:     h.Response,
		Opcode: dns.OpcodeToString[h.Opcode],
		AA:     h.Authoritative,
		TC:     h.Truncated,
		RD:     h.RecursionDesired,
		RA:     h.RecursionAvailable,
		Z:      h.Zero,
		AD:     h.AuthenticatedData,
		CD:     h.CheckingDisabled,
		Rcode:  dns.RcodeToString[h.Rcode],
	}
}

func hdrFromJSON(j MsgHdr) dns.MsgHdr {
	mh := dns.MsgHdr{}
	mh.Response = j.QR
	mh.Opcode = stringToOpcode(j.Opcode)
	mh.Authoritative = j.AA
	mh.Truncated = j.TC
	mh.RecursionDesired = j.RD
	mh.RecursionAvailable = j.RA
	mh.Zero = j.Z
	mh.AuthenticatedData = j.AD
	mh.CheckingDisabled = j.CD
	mh.Rcode = stringToRcode(j.Rcode)
	return mh
}

func rrsToJSON(rrs []dns.RR) ([]RRJSON, error) {
	out := make([]RRJSON, 0, len(rrs))
	for _, rr := range rrs {
		j, err := rrToJSON(rr)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, nil
}

func rrsFromJSON(rrjs []RRJSON) ([]dns.RR, error) {
	out := make([]dns.RR, 0, len(rrjs))
	for _, j := range rrjs {
		rr, err := rrFromJSON(j)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, nil
}

func rrToJSON(rr dns.RR) (RRJSON, error) {
	h := rr.Header()
	j := RRJSON{
		Name:  h.Name,
		Type:  typeToString(h.Rrtype),
		Class: classToString(h.Class),
		TTL:   h.Ttl,
		Data:  map[string]any{},
	}
	switch v := rr.(type) {
	case *dns.A:
		j.Data["a"] = v.A.String()
	case *dns.AAAA:
		j.Data["aaaa"] = v.AAAA.String()
	case *dns.CNAME:
		j.Data["target"] = v.Target
	case *dns.NS:
		j.Data["ns"] = v.Ns
	case *dns.PTR:
		j.Data["ptr"] = v.Ptr
	case *dns.TXT:
		j.Data["txt"] = append([]string(nil), v.Txt...)
	case *dns.MX:
		j.Data["preference"] = v.Preference
		j.Data["mx"] = v.Mx
	case *dns.SRV:
		j.Data["priority"] = v.Priority
		j.Data["weight"] = v.Weight
		j.Data["port"] = v.Port
		j.Data["target"] = v.Target
	case *dns.SOA:
		j.Data["ns"] = v.Ns
		j.Data["mbox"] = v.Mbox
		j.Data["serial"] = v.Serial
		j.Data["refresh"] = v.Refresh
		j.Data["retry"] = v.Retry
		j.Data["expire"] = v.Expire
		j.Data["minttl"] = v.Minttl
	case *dns.CAA:
		j.Data["flag"] = v.Flag
		j.Data["tag"] = v.Tag
		j.Data["value"] = v.Value
	case *dns.NAPTR:
		j.Data["order"] = v.Order
		j.Data["preference"] = v.Preference
		j.Data["flags"] = v.Flags
		j.Data["service"] = v.Service
		j.Data["regexp"] = v.Regexp
		j.Data["replacement"] = v.Replacement
	case *dns.DS:
		j.Data["key_tag"] = v.KeyTag
		j.Data["algorithm"] = v.Algorithm
		j.Data["digest_type"] = v.DigestType
		j.Data["digest"] = strings.ToLower(v.Digest)
	case *dns.DNSKEY:
		j.Data["flags"] = v.Flags
		j.Data["protocol"] = v.Protocol
		j.Data["algorithm"] = v.Algorithm
		j.Data["public_key"] = v.PublicKey
	case *dns.RRSIG:
		j.Data["type_covered"] = typeToString(v.TypeCovered)
		j.Data["algorithm"] = v.Algorithm
		j.Data["labels"] = v.Labels
		j.Data["original_ttl"] = v.OrigTtl
		j.Data["expiration"] = v.Expiration
		j.Data["inception"] = v.Inception
		j.Data["key_tag"] = v.KeyTag
		j.Data["signer_name"] = v.SignerName
		j.Data["signature"] = v.Signature
	case *dns.TLSA:
		j.Data["usage"] = v.Usage
		j.Data["selector"] = v.Selector
		j.Data["matching_type"] = v.MatchingType
		j.Data["cert_data"] = v.Certificate
	default:
		// Fallback to presentation for unknown types to maintain coverage without wire format.
		j.Data["raw"] = rr.String()
	}
	return j, nil
}

func rrFromJSON(j RRJSON) (rr dns.RR, err error) {
	var typeCode, classCode uint16
	if typeCode, err = stringToType(j.Type); err == nil {
		if classCode, err = stringToClass(j.Class); err == nil {
			// Choose concrete by type
			switch typeCode {
			case dns.TypeA:
				ip := net.ParseIP(getString(j.Data, "a"))
				if ip == nil || ip.To4() == nil {
					return nil, fmt.Errorf("A.a must be IPv4")
				}
				r := &dns.A{Hdr: rrHdr(j, typeCode, classCode)}
				r.A = ip.To4()
				return r, nil
			case dns.TypeAAAA:
				ip := net.ParseIP(getString(j.Data, "aaaa"))
				if ip == nil || ip.To16() == nil {
					return nil, fmt.Errorf("AAAA.aaaa must be IPv6")
				}
				rr = &dns.AAAA{
					Hdr:  rrHdr(j, typeCode, classCode),
					AAAA: ip.To16(),
				}
			case dns.TypeCNAME:
				rr = &dns.CNAME{
					Hdr:    rrHdr(j, typeCode, classCode),
					Target: getString(j.Data, "target"),
				}
			case dns.TypeNS:
				rr = &dns.NS{
					Hdr: rrHdr(j, typeCode, classCode),
					Ns:  getString(j.Data, "ns"),
				}
			case dns.TypePTR:
				rr = &dns.PTR{
					Hdr: rrHdr(j, typeCode, classCode),
					Ptr: getString(j.Data, "ptr"),
				}
			case dns.TypeTXT:
				var arr []string
				if arr, err = getStringSlice(j.Data, "txt"); err == nil {
					rr = &dns.TXT{
						Hdr: rrHdr(j, typeCode, classCode),
						Txt: arr,
					}
				}
			case dns.TypeMX:
				rr = &dns.MX{
					Hdr:        rrHdr(j, typeCode, classCode),
					Preference: uint16(getInt(j.Data, "preference")),
					Mx:         getString(j.Data, "mx"),
				}
			case dns.TypeSRV:
				rr = &dns.SRV{
					Hdr:      rrHdr(j, typeCode, classCode),
					Priority: uint16(getInt(j.Data, "priority")),
					Weight:   uint16(getInt(j.Data, "weight")),
					Port:     uint16(getInt(j.Data, "port")),
					Target:   getString(j.Data, "target"),
				}
			case dns.TypeSOA:
				rr = &dns.SOA{
					Hdr:     rrHdr(j, typeCode, classCode),
					Ns:      getString(j.Data, "ns"),
					Mbox:    getString(j.Data, "mbox"),
					Serial:  uint32(getInt(j.Data, "serial")),
					Refresh: uint32(getInt(j.Data, "refresh")),
					Retry:   uint32(getInt(j.Data, "retry")),
					Expire:  uint32(getInt(j.Data, "expire")),
					Minttl:  uint32(getInt(j.Data, "minttl")),
				}
			case dns.TypeCAA:
				rr = &dns.CAA{
					Hdr:   rrHdr(j, typeCode, classCode),
					Flag:  uint8(getInt(j.Data, "flag")),
					Tag:   getString(j.Data, "tag"),
					Value: getString(j.Data, "value"),
				}
			case dns.TypeNAPTR:
				rr = &dns.NAPTR{
					Hdr:         rrHdr(j, typeCode, classCode),
					Order:       uint16(getInt(j.Data, "order")),
					Preference:  uint16(getInt(j.Data, "preference")),
					Flags:       getString(j.Data, "flags"),
					Service:     getString(j.Data, "service"),
					Regexp:      getString(j.Data, "regexp"),
					Replacement: getString(j.Data, "replacement"),
				}
			case dns.TypeDS:
				rr = &dns.DS{
					Hdr:        rrHdr(j, typeCode, classCode),
					KeyTag:     uint16(getInt(j.Data, "key_tag")),
					Algorithm:  uint8(getInt(j.Data, "algorithm")),
					DigestType: uint8(getInt(j.Data, "digest_type")),
					Digest:     strings.ToUpper(getString(j.Data, "digest")),
				}
			case dns.TypeDNSKEY:
				rr = &dns.DNSKEY{
					Hdr:       rrHdr(j, typeCode, classCode),
					Flags:     uint16(getInt(j.Data, "flags")),
					Protocol:  uint8(getInt(j.Data, "protocol")),
					Algorithm: uint8(getInt(j.Data, "algorithm")),
					PublicKey: getString(j.Data, "public_key"),
				}
			case dns.TypeRRSIG:
				var cov uint16
				if cov, err = stringToType(getString(j.Data, "type_covered")); err == nil {
					rr = &dns.RRSIG{
						Hdr:         rrHdr(j, typeCode, classCode),
						TypeCovered: cov,
						Algorithm:   uint8(getInt(j.Data, "algorithm")),
						Labels:      uint8(getInt(j.Data, "labels")),
						OrigTtl:     uint32(getInt(j.Data, "original_ttl")),
						Expiration:  uint32(getInt(j.Data, "expiration")),
						Inception:   uint32(getInt(j.Data, "inception")),
						KeyTag:      uint16(getInt(j.Data, "key_tag")),
						SignerName:  getString(j.Data, "signer_name"),
						Signature:   getString(j.Data, "signature"),
					}
				}
			case dns.TypeTLSA:
				rr = &dns.TLSA{
					Hdr:          rrHdr(j, typeCode, classCode),
					Usage:        uint8(getInt(j.Data, "usage")),
					Selector:     uint8(getInt(j.Data, "selector")),
					MatchingType: uint8(getInt(j.Data, "matching_type")),
					Certificate:  getString(j.Data, "cert_data"),
				}
			default:
				// Best-effort fallback using presentation format stored in data.raw
				raw := getString(j.Data, "raw")
				if raw == "" {
					// try to synthesize: "Name TTL Class Type <empty>"
					raw = fmt.Sprintf("%s %d %s %s", j.Name, j.TTL, j.Class, j.Type)
				}
				if rr, err = dns.NewRR(raw); err == nil {
					// NewRR does not preserve TTL/class/name from header in raw string if omitted; ensure header set
					h := rr.Header()
					h.Name, h.Class, h.Rrtype, h.Ttl = j.Name, classCode, typeCode, j.TTL
					rr.Header().Name = h.Name
					rr.Header().Class = h.Class
					rr.Header().Rrtype = h.Rrtype
					rr.Header().Ttl = h.Ttl
				}
			}
		}
	}
	return
}

func rrHdr(j RRJSON, t uint16, c uint16) dns.RR_Header {
	return dns.RR_Header{Name: j.Name, Rrtype: t, Class: c, Ttl: j.TTL}
}

// --- mapping helpers ---

func typeToString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return strconv.FormatUint(uint64(t), 10)
}
func classToString(c uint16) string {
	if s, ok := dns.ClassToString[c]; ok {
		return s
	}
	return strconv.FormatUint(uint64(c), 10)
}
func stringToType(s string) (uint16, error) {
	if v, ok := dns.StringToType[strings.ToUpper(s)]; ok {
		return v, nil
	}
	// numeric?
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(n), nil
	}
	return 0, fmt.Errorf("unknown type %q", s)
}
func stringToClass(s string) (uint16, error) {
	if v, ok := dns.StringToClass[strings.ToUpper(s)]; ok {
		return v, nil
	}
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(n), nil
	}
	return 0, fmt.Errorf("unknown class %q", s)
}
func stringToOpcode(s string) int {
	for k, v := range dns.OpcodeToString {
		if v == strings.ToUpper(s) {
			return k
		}
	}
	return dns.OpcodeQuery
}
func stringToRcode(s string) int {
	for k, v := range dns.RcodeToString {
		if v == strings.ToUpper(s) {
			return k
		}
	}
	return dns.RcodeSuccess
}

// --- small JSON helpers ---

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
func getInt(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int:
		return int64(t)
	case int64:
		return t
	case json.Number:
		i, _ := t.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(t, 10, 64)
		return i
	default:
		return 0
	}
}
func getStringSlice(m map[string]any, key string) ([]string, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be array of strings", key)
	}
	out := make([]string, 0, len(a))
	for _, it := range a {
		s, ok := it.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be array of strings", key)
		}
		out = append(out, s)
	}
	return out, nil
}
