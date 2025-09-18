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
	j.Answer = rrsToJSON(m.Answer)
	j.Ns = rrsToJSON(m.Ns)
	j.Extra = rrsToJSON(m.Extra)
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

func hdrFromJSON(j MsgHdr) (mh dns.MsgHdr) {
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
	return
}

func rrsToJSON(rrs []dns.RR) (out []RRJSON) {
	for _, rr := range rrs {
		out = append(out, rrToJSON(rr))
	}
	return
}

func rrsFromJSON(rrjs []RRJSON) (out []dns.RR, err error) {
	for _, j := range rrjs {
		if rr, e := rrFromJSON(j); e == nil {
			out = append(out, rr)
		} else {
			err = errors.Join(err, e)
		}
	}
	return
}

func rrToJSON(rr dns.RR) RRJSON {
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
	return j
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
					Preference: getUint16(j.Data, "preference"),
					Mx:         getString(j.Data, "mx"),
				}
			case dns.TypeSRV:
				rr = &dns.SRV{
					Hdr:      rrHdr(j, typeCode, classCode),
					Priority: getUint16(j.Data, "priority"),
					Weight:   getUint16(j.Data, "weight"),
					Port:     getUint16(j.Data, "port"),
					Target:   getString(j.Data, "target"),
				}
			case dns.TypeSOA:
				rr = &dns.SOA{
					Hdr:     rrHdr(j, typeCode, classCode),
					Ns:      getString(j.Data, "ns"),
					Mbox:    getString(j.Data, "mbox"),
					Serial:  getUint32(j.Data, "serial"),
					Refresh: getUint32(j.Data, "refresh"),
					Retry:   getUint32(j.Data, "retry"),
					Expire:  getUint32(j.Data, "expire"),
					Minttl:  getUint32(j.Data, "minttl"),
				}
			case dns.TypeCAA:
				rr = &dns.CAA{
					Hdr:   rrHdr(j, typeCode, classCode),
					Flag:  getUint8(j.Data, "flag"),
					Tag:   getString(j.Data, "tag"),
					Value: getString(j.Data, "value"),
				}
			case dns.TypeNAPTR:
				rr = &dns.NAPTR{
					Hdr:         rrHdr(j, typeCode, classCode),
					Order:       getUint16(j.Data, "order"),
					Preference:  getUint16(j.Data, "preference"),
					Flags:       getString(j.Data, "flags"),
					Service:     getString(j.Data, "service"),
					Regexp:      getString(j.Data, "regexp"),
					Replacement: getString(j.Data, "replacement"),
				}
			case dns.TypeDS:
				rr = &dns.DS{
					Hdr:        rrHdr(j, typeCode, classCode),
					KeyTag:     getUint16(j.Data, "key_tag"),
					Algorithm:  getUint8(j.Data, "algorithm"),
					DigestType: getUint8(j.Data, "digest_type"),
					Digest:     strings.ToUpper(getString(j.Data, "digest")),
				}
			case dns.TypeDNSKEY:
				rr = &dns.DNSKEY{
					Hdr:       rrHdr(j, typeCode, classCode),
					Flags:     getUint16(j.Data, "flags"),
					Protocol:  getUint8(j.Data, "protocol"),
					Algorithm: getUint8(j.Data, "algorithm"),
					PublicKey: getString(j.Data, "public_key"),
				}
			case dns.TypeRRSIG:
				var cov uint16
				if cov, err = stringToType(getString(j.Data, "type_covered")); err == nil {
					rr = &dns.RRSIG{
						Hdr:         rrHdr(j, typeCode, classCode),
						TypeCovered: cov,
						Algorithm:   getUint8(j.Data, "algorithm"),
						Labels:      getUint8(j.Data, "labels"),
						OrigTtl:     getUint32(j.Data, "original_ttl"),
						Expiration:  getUint32(j.Data, "expiration"),
						Inception:   getUint32(j.Data, "inception"),
						KeyTag:      getUint16(j.Data, "key_tag"),
						SignerName:  getString(j.Data, "signer_name"),
						Signature:   getString(j.Data, "signature"),
					}
				}
			case dns.TypeTLSA:
				rr = &dns.TLSA{
					Hdr:          rrHdr(j, typeCode, classCode),
					Usage:        getUint8(j.Data, "usage"),
					Selector:     getUint8(j.Data, "selector"),
					MatchingType: getUint8(j.Data, "matching_type"),
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

func typeToString(t uint16) (s string) {
	var ok bool
	if s, ok = dns.TypeToString[t]; !ok {
		s = strconv.FormatUint(uint64(t), 10)
	}
	return
}

func stringToType(s string) (typ uint16, err error) {
	var ok bool
	if typ, ok = dns.StringToType[strings.ToUpper(s)]; !ok {
		var n uint64
		if n, err = strconv.ParseUint(s, 10, 16); err == nil {
			typ = uint16(n)
		} else {
			err = fmt.Errorf("unknown type %q", s)
		}
	}
	return
}

func classToString(c uint16) (s string) {
	var ok bool
	if s, ok = dns.ClassToString[c]; !ok {
		s = strconv.FormatUint(uint64(c), 10)
	}
	return
}

func stringToClass(s string) (cls uint16, err error) {
	var ok bool
	if cls, ok = dns.StringToClass[strings.ToUpper(s)]; !ok {
		var n uint64
		if n, err = strconv.ParseUint(s, 10, 16); err == nil {
			cls = uint16(n)
		} else {
			err = fmt.Errorf("unknown class %q", s)
		}
	}
	return
}

func stringToOpcode(s string) (opcode int) {
	opcode = dns.OpcodeQuery
	if op, ok := dns.StringToOpcode[strings.ToUpper(s)]; ok {
		opcode = op
	}
	return
}

func stringToRcode(s string) (rcode int) {
	rcode = dns.RcodeSuccess
	if rc, ok := dns.StringToRcode[strings.ToUpper(s)]; ok {
		rcode = rc
	}
	return
}

// --- small JSON helpers ---

func getString(m map[string]any, key string) (s string) {
	if m != nil {
		if v, ok := m[key]; ok {
			s, _ = v.(string)
		}
	}
	return
}

func getUint8(m map[string]any, key string) uint8 {
	return uint8(getInt(m, key)) // #nosec G115
}
func getUint16(m map[string]any, key string) uint16 {
	return uint16(getInt(m, key)) // #nosec G115
}
func getUint32(m map[string]any, key string) uint32 {
	return uint32(getInt(m, key)) // #nosec G115
}

func getInt(m map[string]any, key string) (n int64) {
	if m != nil {
		if v, ok := m[key]; ok {
			switch t := v.(type) {
			case float64:
				n = int64(t)
			case int:
				n = int64(t)
			case int64:
				n = t
			case json.Number:
				n, _ = t.Int64()
			case string:
				n, _ = strconv.ParseInt(t, 10, 64)
			}
		}
	}
	return
}

func getStringSlice(m map[string]any, key string) (out []string, err error) {
	if v, ok := m[key]; ok {
		a, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("%s must be array of strings", key)
		}
		for _, it := range a {
			s, ok := it.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be array of strings", key)
			}
			out = append(out, s)
		}
	}
	return
}
