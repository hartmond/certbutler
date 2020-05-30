package acme

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

var (
	records = []string{}
	mux     sync.Mutex
)

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
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

func hostDNS(tokens []string) chan bool {
	mux.Lock()

	records = tokens
	done := make(chan bool)

	dns.HandleFunc(".", handleDNSRequest)
	server := &dns.Server{Addr: ":53", Net: "udp"}

	go func() {
		<-done
		server.Shutdown()
		mux.Unlock()
	}()

	go server.ListenAndServe() // TODO somehow catch error when startup fails
	return done
}
