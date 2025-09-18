package dnsjson_test

import (
	"encoding/json"
	"fmt"

	"github.com/linkdata/dnsjson"
	"github.com/miekg/dns"
)

func Example() {
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
