[![build](https://github.com/linkdata/dnsjson/actions/workflows/build.yml/badge.svg)](https://github.com/linkdata/dnsjson/actions/workflows/build.yml)
[![coverage](https://github.com/linkdata/dnsjson/blob/coverage/main/badge.svg)](https://htmlpreview.github.io/?https://github.com/linkdata/dnsjson/blob/coverage/main/report.html)
[![goreport](https://goreportcard.com/badge/github.com/linkdata/dnsjson)](https://goreportcard.com/report/github.com/linkdata/dnsjson)
[![Docs](https://godoc.org/github.com/linkdata/dnsjson?status.svg)](https://godoc.org/github.com/linkdata/dnsjson)

# dnsjson

JSON (un)marshalling for https://github.com/miekg/dns

```go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/linkdata/dnsjson"
	"github.com/miekg/dns"
)

func main() {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Id = 1234
	jbytes, err := json.MarshalIndent((*dnsjson.Msg)(msg), "", " ")
	if err == nil {
		fmt.Println(string(jbytes))
		var msg2 dnsjson.Msg
		if err = json.Unmarshal(jbytes, &msg2); err == nil {
			fmt.Println(dns.Msg(msg2).Question[0].Name)
		}
	}
	if err != nil {
		fmt.Println(err)
	}

	// Output:
	// {
	//  "id": 1234,
	//  "msgHdr": {
	//   "opcode": "QUERY",
	//   "rd": true,
	//   "rcode": "NOERROR"
	//  },
	//  "question": [
	//   {
	//    "name": "example.com.",
	//    "qtype": "A",
	//    "qclass": "IN"
	//   }
	//  ]
	// }
	// example.com.
}
```
