package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jaxxstorm/dnsscale/providers"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func TestRFC2136Config(t *testing.T) {
	t.Setenv("TAILSCALE_API_KEY", "test-key")
	t.Setenv("TAILSCALE_TAILNET", "test-tailnet")
	t.Setenv("DNS_PROVIDER", "rfc2136")
	t.Setenv("DNS_DOMAIN", "nodes.example.com")
	t.Setenv("RFC2136_SERVER", "127.0.0.1:5353")
	t.Setenv("RFC2136_ZONE", "example.com")
	t.Setenv("RFC2136_TSIG_KEY_NAME", "dnsscale.")
	t.Setenv("RFC2136_TSIG_SECRET", "dGVzdC1vbmx5LXNlY3JldA==")
	t.Setenv("RFC2136_TIMEOUT", "5s")
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if config.DNS.RFC2136.Timeout != 5*time.Second || config.DNS.RFC2136.Zone != "example.com" {
		t.Fatalf("unexpected environment configuration: %+v", config.DNS.RFC2136)
	}
	provider, err := createDNSProvider(context.Background(), &config, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := provider.(*providers.RFC2136Provider); !ok {
		t.Fatalf("unexpected provider: %T", provider)
	}
	config.DNS.RFC2136.Zone = ""
	if err := config.Validate(); err != nil || config.DNS.RFC2136.Zone != config.DNS.Domain {
		t.Fatalf("zone did not default to domain: %v", err)
	}
	config.DNS.RFC2136.Zone = "other.com"
	if err := config.Validate(); err == nil {
		t.Fatal("expected out-of-zone configuration error")
	}
}

func TestReconcilerShutdown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"devices":[]}`))
	}))
	defer server.Close()
	client := NewTailscaleClient("test-key", "test-tailnet", zap.NewNop())
	client.baseURL = server.URL
	reconciler := NewDNSReconciler(client, nil, "example.com", time.Hour, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx, 2) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle workers prevented graceful shutdown")
	}
}
