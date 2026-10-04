package netguard

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDiagnosticIPBoundary(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	for _, raw := range []string{"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "fd00:ec2::254", "::ffff:127.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1", "2001:db8::1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "0.1.2.3"} {
		if telegramIPAllowed(net.ParseIP(raw)) {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{"149.154.167.220", "2001:b28:f23d:f001::e"} {
		if !telegramIPAllowed(net.ParseIP(raw)) {
			t.Errorf("rejected public %s", raw)
		}
	}
}

func TestDiagnosticDialPinsValidatedIP(t *testing.T) {
	lookups, dials := 0, 0
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		if host != "api.telegram.org" {
			t.Fatal(host)
		}
		return []net.IPAddr{{IP: net.ParseIP("149.154.167.220")}}, nil
	}
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		dials++
		if address != "149.154.167.220:443" {
			t.Fatal("DNS rebound", address)
		}
		return nil, errors.New("synthetic dial")
	}
	_, _ = telegramDial(context.Background(), "tcp", "api.telegram.org:443", lookup, dial)
	if lookups != 1 || dials != 1 {
		t.Fatal(lookups, dials)
	}
	for _, address := range []string{"evil.test:443", "api.telegram.org:80", "127.0.0.1:443"} {
		_, _ = telegramDial(context.Background(), "tcp", address, lookup, dial)
	}
	if lookups != 1 || dials != 1 {
		t.Fatal("allowlist bypass")
	}
	lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("149.154.167.220")}, {IP: net.ParseIP("10.0.0.1")}}, nil
	}
	_, _ = telegramDial(context.Background(), "tcp", "api.telegram.org:443", lookup, dial)
	if dials != 1 {
		t.Fatal("mixed private DNS accepted")
	}
}
