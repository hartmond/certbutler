package acme

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

var (
	records = []string{}
	server  *dns.Server
)

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if r.Opcode == dns.OpcodeQuery {
		for _, q := range m.Question {
			for _, record := range records {
				rr, err := dns.NewRR(fmt.Sprintf("%s 0 IN TXT %s", q.Name, record))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}

	w.WriteMsg(m)
}

func addDNSToken(token string) {
	records = append(records, token)
	go startServer()
}

func clearDNSTokens() {
	if server != nil {
		records = []string{}
		server.Shutdown()
	}
}

func startServer() {
	if server != nil {
		return
	}
	dns.HandleFunc(".", handleDnsRequest)
	server = &dns.Server{Addr: ":53", Net: "udp"}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
	server = nil
}
