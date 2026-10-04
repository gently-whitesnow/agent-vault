package netguard

import (
	"context"
	"errors"
	"net"
	"time"
)

func TelegramDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return telegramDial(ctx, network, address, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
}

func telegramDial(ctx context.Context, network, address string, lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if address != "api.telegram.org:443" || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, errors.New("diagnostic destination forbidden")
	}
	ips, err := lookup(ctx, "api.telegram.org")
	if err != nil || len(ips) == 0 {
		return nil, errors.New("diagnostic DNS unavailable")
	}
	for _, address := range ips {
		if !telegramIPAllowed(address.IP) || address.Zone != "" {
			return nil, errors.New("diagnostic destination forbidden")
		}
	}
	return dial(ctx, network, net.JoinHostPort(ips[0].IP.String(), "443"))
}

var diagnosticBlocked = []net.IPNet{
	parseCIDR("0.0.0.0/8"), parseCIDR("192.0.0.0/24"), parseCIDR("192.0.2.0/24"),
	parseCIDR("192.88.99.0/24"), parseCIDR("198.18.0.0/15"), parseCIDR("198.51.100.0/24"),
	parseCIDR("203.0.113.0/24"), parseCIDR("240.0.0.0/4"),
	parseCIDR("2001::/23"), parseCIDR("2001:db8::/32"), parseCIDR("2002::/16"),
}
var diagnosticIPv6Global = parseCIDR("2000::/3")

func telegramIPAllowed(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || isBlockedIP(ip, false, nil) {
		return false
	}
	if ip.To4() == nil && !diagnosticIPv6Global.Contains(ip) {
		return false
	}
	for _, blocked := range diagnosticBlocked {
		if blocked.Contains(ip) {
			return false
		}
	}
	return true
}
