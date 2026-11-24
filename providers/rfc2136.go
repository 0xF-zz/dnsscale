package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type RFC2136Config struct {
	Server        string        `mapstructure:"server" yaml:"server"`
	Zone          string        `mapstructure:"zone" yaml:"zone,omitempty"`
	TSIGKeyName   string        `mapstructure:"tsig_key_name" yaml:"tsig_key_name,omitempty"`
	TSIGSecret    string        `mapstructure:"tsig_secret" yaml:"tsig_secret,omitempty"`
	TSIGAlgorithm string        `mapstructure:"tsig_algorithm" yaml:"tsig_algorithm,omitempty"`
	Timeout       time.Duration `mapstructure:"timeout" yaml:"timeout,omitempty"`
}

type RFC2136Provider struct {
	config RFC2136Config
	client *dns.Client
}

func NewRFC2136Provider(config RFC2136Config) (*RFC2136Provider, error) {
	host, port, err := net.SplitHostPort(config.Server)
	if err != nil || host == "" {
		return nil, fmt.Errorf("dns.rfc2136.server must be a host:port address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("dns.rfc2136.server must have a valid port")
	}
	config.Zone = dns.Fqdn(config.Zone)
	if _, ok := dns.IsDomainName(config.Zone); !ok || config.Zone == "." {
		return nil, fmt.Errorf("dns.rfc2136.zone must be a valid non-root DNS zone")
	}
	if config.Timeout < 0 {
		return nil, fmt.Errorf("dns.rfc2136.timeout must be positive")
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	client := &dns.Client{Net: "tcp", Timeout: config.Timeout}
	if config.TSIGKeyName != "" || config.TSIGSecret != "" || config.TSIGAlgorithm != "" {
		if config.TSIGKeyName == "" || config.TSIGSecret == "" {
			return nil, fmt.Errorf("dns.rfc2136.tsig_key_name and tsig_secret must be provided together")
		}
		config.TSIGKeyName = dns.CanonicalName(config.TSIGKeyName)
		if _, ok := dns.IsDomainName(config.TSIGKeyName); !ok {
			return nil, fmt.Errorf("dns.rfc2136.tsig_key_name must be a valid DNS name")
		}
		secret, err := base64.StdEncoding.DecodeString(config.TSIGSecret)
		if err != nil || len(secret) == 0 {
			return nil, fmt.Errorf("dns.rfc2136.tsig_secret must be a non-empty base64-encoded key")
		}
		if config.TSIGAlgorithm == "" {
			config.TSIGAlgorithm = dns.HmacSHA256
		}
		config.TSIGAlgorithm = dns.Fqdn(strings.ToLower(config.TSIGAlgorithm))
		switch config.TSIGAlgorithm {
		case dns.HmacSHA1, dns.HmacSHA224, dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512:
		default:
			return nil, fmt.Errorf("unsupported dns.rfc2136.tsig_algorithm: %s", config.TSIGAlgorithm)
		}
		client.TsigSecret = map[string]string{config.TSIGKeyName: config.TSIGSecret}
	}
	return &RFC2136Provider{config: config, client: client}, nil
}

func (p *RFC2136Provider) sign(msg *dns.Msg) {
	if p.config.TSIGKeyName != "" {
		msg.SetTsig(p.config.TSIGKeyName, p.config.TSIGAlgorithm, 300, time.Now().Unix())
	}
}

func (p *RFC2136Provider) validateZone(zone string) error {
	if _, ok := dns.IsDomainName(zone); !ok || !dns.IsSubDomain(p.config.Zone, dns.Fqdn(zone)) {
		return fmt.Errorf("domain %q is outside RFC 2136 zone %s", zone, p.config.Zone)
	}
	return nil
}

func (p *RFC2136Provider) record(zone string, record DNSRecord) (dns.RR, error) {
	if err := p.validateZone(zone); err != nil {
		return nil, err
	}
	name := dns.Fqdn(record.Name)
	if _, ok := dns.IsDomainName(name); !ok || !dns.IsSubDomain(dns.Fqdn(zone), name) {
		return nil, fmt.Errorf("record name %q is outside domain %s", record.Name, zone)
	}
	if record.TTL < 0 || record.TTL > math.MaxUint32 {
		return nil, fmt.Errorf("record TTL must be between 0 and %d", uint64(math.MaxUint32))
	}
	header := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: uint32(record.TTL)}
	switch record.Type {
	case "A":
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid A record address %q", record.Value)
		}
		header.Rrtype = dns.TypeA
		return &dns.A{Hdr: header, A: ip.To4()}, nil
	case "AAAA":
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("invalid AAAA record address %q", record.Value)
		}
		header.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: header, AAAA: ip}, nil
	case "TXT":
		// The reconciler supplies quoted presentation-format TXT values.
		value := record.Value
		if !strings.HasPrefix(value, `"`) {
			value = strconv.Quote(value)
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", name, record.TTL, value))
		if err != nil {
			return nil, fmt.Errorf("invalid TXT record: %w", err)
		}
		return rr, nil
	default:
		return nil, fmt.Errorf("unsupported RFC 2136 record type %q", record.Type)
	}
}

func (p *RFC2136Provider) update(ctx context.Context, msg *dns.Msg) error {
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	conn, err := p.client.DialContext(ctx, p.config.Server)
	if err != nil {
		return fmt.Errorf("RFC 2136 update connection failed: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	p.sign(msg)
	response, _, err := p.client.ExchangeWithConnContext(ctx, msg, conn)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("RFC 2136 update canceled: %w", ctx.Err())
		}
		return fmt.Errorf("RFC 2136 update failed: %w", err)
	}
	if p.config.TSIGKeyName != "" && response.IsTsig() == nil {
		return fmt.Errorf("RFC 2136 response is missing TSIG authentication")
	}
	if !response.Response || response.Truncated || response.Opcode != dns.OpcodeUpdate || response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("RFC 2136 update rejected: %s (opcode %d)", dns.RcodeToString[response.Rcode], response.Opcode)
	}
	return nil
}

func (p *RFC2136Provider) CreateRecord(ctx context.Context, zone string, record DNSRecord) error {
	rr, err := p.record(zone, record)
	if err != nil {
		return err
	}
	msg := new(dns.Msg)
	msg.SetUpdate(p.config.Zone)
	msg.Insert([]dns.RR{rr})
	return p.update(ctx, msg)
}

func (p *RFC2136Provider) UpdateRecord(ctx context.Context, zone string, record DNSRecord) error {
	rr, err := p.record(zone, record)
	if err != nil {
		return err
	}
	msg := new(dns.Msg)
	msg.SetUpdate(p.config.Zone)
	msg.RemoveRRset([]dns.RR{rr})
	msg.Insert([]dns.RR{rr})
	return p.update(ctx, msg)
}

func (p *RFC2136Provider) DeleteRecord(ctx context.Context, zone string, record DNSRecord) error {
	rr, err := p.record(zone, record)
	if err != nil {
		return err
	}
	msg := new(dns.Msg)
	msg.SetUpdate(p.config.Zone)
	msg.Remove([]dns.RR{rr})
	return p.update(ctx, msg)
}

func (p *RFC2136Provider) ListRecords(ctx context.Context, zone string) ([]DNSRecord, error) {
	if err := p.validateZone(zone); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.config.Server)
	if err != nil {
		return nil, fmt.Errorf("RFC 2136 AXFR connection failed: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	transfer := &dns.Transfer{
		Conn:        &dns.Conn{Conn: conn},
		ReadTimeout: p.config.Timeout,
		TsigSecret:  p.client.TsigSecret,
	}
	msg := new(dns.Msg)
	msg.SetAxfr(p.config.Zone)
	p.sign(msg)
	envelopes, err := transfer.In(msg, p.config.Server)
	if err != nil {
		return nil, fmt.Errorf("RFC 2136 AXFR failed: %w", err)
	}
	var records []DNSRecord
	var transferErr error
	// Drain the channel even after errors so the transfer goroutine can exit.
	for envelope := range envelopes {
		if envelope.Error != nil {
			transferErr = envelope.Error
			continue
		}
		for _, rr := range envelope.RR {
			if !dns.IsSubDomain(dns.Fqdn(zone), rr.Header().Name) {
				continue
			}
			record := DNSRecord{Name: rr.Header().Name, TTL: int64(rr.Header().Ttl)}
			switch rr := rr.(type) {
			case *dns.A:
				record.Type, record.Value = "A", rr.A.String()
			case *dns.AAAA:
				record.Type, record.Value = "AAAA", rr.AAAA.String()
			case *dns.TXT:
				record.Type, record.Value = "TXT", strings.TrimPrefix(rr.String(), rr.Hdr.String())
			default:
				continue
			}
			records = append(records, record)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("RFC 2136 AXFR canceled: %w", err)
	}
	if transferErr != nil {
		return nil, fmt.Errorf("RFC 2136 AXFR failed: %w", transferErr)
	}
	return records, nil
}
