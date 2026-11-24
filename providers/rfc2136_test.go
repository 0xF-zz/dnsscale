package providers

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testTSIGSecret = "dGVzdC1vbmx5LXNlY3JldA=="

func startDNSServer(t *testing.T, secrets map[string]string, handler dns.HandlerFunc) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{
		Listener: listener, Handler: handler, TsigSecret: secrets,
		NotifyStartedFunc: func() { close(started) },
		MsgAcceptFunc:     func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept },
	}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return listener.Addr().String()
}

func replyDNS(t *testing.T, w dns.ResponseWriter, request *dns.Msg, rcode int, signed bool) {
	t.Helper()
	response := new(dns.Msg)
	response.SetRcode(request, rcode)
	if tsig := request.IsTsig(); signed && tsig != nil {
		response.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
	}
	if err := w.WriteMsg(response); err != nil {
		t.Error(err)
	}
}

func TestRFC2136Records(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsigned", true: "TSIG"}[signed], func(t *testing.T) {
			var mutex sync.Mutex
			var records []dns.RR
			secrets := map[string]string{"dnsscale.": testTSIGSecret}
			address := startDNSServer(t, secrets, func(w dns.ResponseWriter, request *dns.Msg) {
				mutex.Lock()
				defer mutex.Unlock()
				if signed && (request.IsTsig() == nil || w.TsigStatus() != nil) {
					t.Errorf("request was not authenticated: %v", w.TsigStatus())
					replyDNS(t, w, request, dns.RcodeNotAuth, false)
					return
				}
				if request.Question[0].Name != "example.com." {
					t.Errorf("wrong authoritative zone: %s", request.Question[0].Name)
				}
				if request.Opcode == dns.OpcodeUpdate {
					for _, rr := range request.Ns {
						switch rr.Header().Class {
						case dns.ClassANY:
							var kept []dns.RR
							for _, existing := range records {
								if existing.Header().Name != rr.Header().Name || existing.Header().Rrtype != rr.Header().Rrtype {
									kept = append(kept, existing)
								}
							}
							records = kept
						case dns.ClassNONE:
							deleted := dns.Copy(rr)
							deleted.Header().Class = dns.ClassINET
							var kept []dns.RR
							for _, existing := range records {
								if !dns.IsDuplicate(existing, deleted) {
									kept = append(kept, existing)
								}
							}
							records = kept
						case dns.ClassINET:
							records = append(records, rr)
						default:
							t.Errorf("unexpected update class: %d", rr.Header().Class)
						}
					}
					replyDNS(t, w, request, dns.RcodeSuccess, signed)
					return
				}
				if request.Question[0].Qtype != dns.TypeAXFR {
					t.Errorf("expected AXFR, got %d", request.Question[0].Qtype)
				}
				soa, err := dns.NewRR("example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 300")
				if err != nil {
					t.Error(err)
					return
				}
				channel := make(chan *dns.Envelope, 2)
				channel <- &dns.Envelope{RR: append([]dns.RR{soa}, records...)}
				channel <- &dns.Envelope{RR: []dns.RR{soa}}
				close(channel)
				if err := new(dns.Transfer).Out(w, request, channel); err != nil {
					t.Error(err)
				}
			})
			config := RFC2136Config{Server: address, Zone: "example.com"}
			if signed {
				config.TSIGKeyName, config.TSIGSecret = "DNSScale", testTSIGSecret
			}
			provider, err := NewRFC2136Provider(config)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			for _, record := range []DNSRecord{
				{Name: "host.nodes.example.com", Type: "A", Value: "100.64.0.1", TTL: 300},
				{Name: "host.nodes.example.com", Type: "A", Value: "100.64.0.2", TTL: 300},
				{Name: "host.nodes.example.com", Type: "AAAA", Value: "fd7a:115c:a1e0::1", TTL: 300},
				{Name: "host.nodes.example.com", Type: "TXT", Value: `"dnsscale-managed node_id=123"`, TTL: 300},
				{Name: "host.nodes.example.com", Type: "TXT", Value: `"multiple" "segments \"quoted\""`, TTL: 300},
				{Name: "other.example.com", Type: "A", Value: "192.0.2.1", TTL: 300},
			} {
				if err := provider.CreateRecord(ctx, "example.com", record); err != nil {
					t.Fatal(err)
				}
			}
			replacement := DNSRecord{Name: "host.nodes.example.com", Type: "A", Value: "100.64.0.3", TTL: 600}
			if err := provider.UpdateRecord(ctx, "nodes.example.com", replacement); err != nil {
				t.Fatal(err)
			}
			listed, err := provider.ListRecords(ctx, "nodes.example.com")
			if err != nil {
				t.Fatal(err)
			}
			expected := []DNSRecord{
				{Name: "host.nodes.example.com.", Type: "AAAA", Value: "fd7a:115c:a1e0::1", TTL: 300},
				{Name: "host.nodes.example.com.", Type: "TXT", Value: `"dnsscale-managed node_id=123"`, TTL: 300},
				{Name: "host.nodes.example.com.", Type: "TXT", Value: `"multiple" "segments \"quoted\""`, TTL: 300},
				{Name: "host.nodes.example.com.", Type: "A", Value: "100.64.0.3", TTL: 600},
			}
			if !reflect.DeepEqual(listed, expected) {
				t.Fatalf("records = %#v, want %#v", listed, expected)
			}
			for _, record := range listed {
				if err := provider.DeleteRecord(ctx, "nodes.example.com", record); err != nil {
					t.Fatal(err)
				}
			}
			listed, err = provider.ListRecords(ctx, "nodes.example.com")
			if err != nil || len(listed) != 0 {
				t.Fatalf("records after deletion = %v, error = %v", listed, err)
			}
		})
	}
}

func TestRFC2136Errors(t *testing.T) {
	for _, test := range []struct {
		name   string
		rcode  int
		signed bool
		secret string
	}{
		{name: "refused", rcode: dns.RcodeRefused, signed: true, secret: testTSIGSecret},
		{name: "missing TSIG", rcode: dns.RcodeSuccess, secret: testTSIGSecret},
		{name: "wrong key", rcode: dns.RcodeSuccess, signed: true, secret: "d3Jvbmc="},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := startDNSServer(t, map[string]string{"dnsscale.": testTSIGSecret}, func(w dns.ResponseWriter, request *dns.Msg) {
				replyDNS(t, w, request, test.rcode, test.signed)
			})
			provider, err := NewRFC2136Provider(RFC2136Config{
				Server: address, Zone: "example.com", TSIGKeyName: "dnsscale.", TSIGSecret: test.secret,
			})
			if err != nil {
				t.Fatal(err)
			}
			record := DNSRecord{Name: "host.example.com", Type: "A", Value: "100.64.0.1", TTL: 300}
			if err := provider.UpdateRecord(context.Background(), "example.com", record); err == nil {
				t.Fatal("expected update error")
			}
			if _, err := provider.ListRecords(context.Background(), "example.com"); err == nil {
				t.Fatal("expected AXFR error")
			}
		})
	}
}

func TestRFC2136Validation(t *testing.T) {
	for _, config := range []RFC2136Config{
		{Server: "", Zone: "example.com"},
		{Server: "localhost:0", Zone: "example.com"},
		{Server: "localhost:65536", Zone: "example.com"},
		{Server: "localhost:53", Zone: ""},
		{Server: "localhost:53", Zone: "example.com", Timeout: -time.Second},
		{Server: "localhost:53", Zone: "example.com", TSIGKeyName: "key"},
		{Server: "localhost:53", Zone: "example.com", TSIGSecret: testTSIGSecret},
		{Server: "localhost:53", Zone: "example.com", TSIGKeyName: "key", TSIGSecret: "not-base64"},
		{Server: "localhost:53", Zone: "example.com", TSIGKeyName: "key", TSIGSecret: testTSIGSecret, TSIGAlgorithm: "unsupported"},
	} {
		if _, err := NewRFC2136Provider(config); err == nil {
			t.Errorf("expected invalid configuration: %+v", config)
		}
	}
	provider, err := NewRFC2136Provider(RFC2136Config{Server: "[::1]:53", Zone: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []DNSRecord{
		{Name: "host.other.com", Type: "A", Value: "100.64.0.1", TTL: 300},
		{Name: "host.example.com", Type: "A", Value: "::1", TTL: 300},
		{Name: "host.example.com", Type: "AAAA", Value: "100.64.0.1", TTL: 300},
		{Name: "host.example.com", Type: "CNAME", Value: "target.example.com", TTL: 300},
		{Name: "host.example.com", Type: "A", Value: "100.64.0.1", TTL: -1},
		{Name: "host.example.com", Type: "A", Value: "100.64.0.1", TTL: 1 << 32},
		{Name: "host.example.com", Type: "TXT", Value: `"unterminated`, TTL: 300},
	} {
		if _, err := provider.record("example.com", record); err == nil {
			t.Errorf("expected invalid record: %+v", record)
		}
	}
	if _, err := provider.ListRecords(context.Background(), "notexample.com"); err == nil {
		t.Fatal("expected out-of-zone error")
	}
}

func TestRFC2136Cancellation(t *testing.T) {
	for _, operation := range []string{"AXFR", "update"} {
		t.Run(operation, func(t *testing.T) {
			received := make(chan struct{})
			release := make(chan struct{})
			address := startDNSServer(t, nil, func(w dns.ResponseWriter, request *dns.Msg) {
				close(received)
				<-release
			})
			defer close(release)
			provider, err := NewRFC2136Provider(RFC2136Config{Server: address, Zone: "example.com", Timeout: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "AXFR" {
					_, err := provider.ListRecords(ctx, "example.com")
					done <- err
				} else {
					done <- provider.UpdateRecord(ctx, "example.com", DNSRecord{
						Name: "host.example.com", Type: "A", Value: "100.64.0.1", TTL: 300,
					})
				}
			}()
			select {
			case <-received:
			case <-time.After(5 * time.Second):
				t.Fatal("DNS request not received")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), operation) {
					t.Fatalf("expected %s cancellation, got %v", operation, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("DNS operation did not stop on cancellation")
			}
		})
	}
}

func TestRFC2136TSIGAlgorithms(t *testing.T) {
	address := startDNSServer(t, map[string]string{"dnsscale.": testTSIGSecret}, func(w dns.ResponseWriter, request *dns.Msg) {
		if request.IsTsig() == nil || w.TsigStatus() != nil {
			t.Errorf("request was not authenticated: %v", w.TsigStatus())
		}
		replyDNS(t, w, request, dns.RcodeSuccess, true)
	})
	for _, algorithm := range []string{"HMAC-SHA1", "hmac-sha224.", "hmac-sha256", "hmac-sha384", "hmac-sha512"} {
		t.Run(algorithm, func(t *testing.T) {
			provider, err := NewRFC2136Provider(RFC2136Config{
				Server: address, Zone: "example.com",
				TSIGKeyName: "dnsscale.", TSIGSecret: testTSIGSecret, TSIGAlgorithm: algorithm,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.UpdateRecord(context.Background(), "example.com", DNSRecord{
				Name: "host.example.com", Type: "A", Value: "100.64.0.1", TTL: 300,
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRFC2136Timeout(t *testing.T) {
	for _, operation := range []string{"AXFR", "update"} {
		t.Run(operation, func(t *testing.T) {
			release := make(chan struct{})
			address := startDNSServer(t, nil, func(w dns.ResponseWriter, request *dns.Msg) { <-release })
			defer close(release)
			provider, err := NewRFC2136Provider(RFC2136Config{
				Server: address, Zone: "example.com", Timeout: 100 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "AXFR" {
					_, err := provider.ListRecords(ctx, "example.com")
					done <- err
				} else {
					done <- provider.UpdateRecord(ctx, "example.com", DNSRecord{
						Name: "host.example.com", Type: "A", Value: "100.64.0.1", TTL: 300,
					})
				}
			}()
			select {
			case err := <-done:
				var networkError net.Error
				if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &networkError) && networkError.Timeout()) {
					t.Fatalf("expected timeout, got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("configured 100ms timeout was not enforced")
			}
		})
	}
}
