package utils

import (
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// Client IP resolution and rate-limit keys (spec/API_SPEC.md "Client IP
// resolution"). Every feature that keys on the client address uses
// ClientIPResolver so a client can never choose its own key.

// DefaultIPv6Subnet is the prefix length RateLimitKey groups IPv6 addresses
// by, so one IPv6 allocation cannot mint unlimited keys.
const DefaultIPv6Subnet = 56

// UnknownClientKey is the shared key for requests whose client address cannot
// be determined. It never equals a real client key.
const UnknownClientKey = "unknown"

// defaultTrustedProxies equals Express's `trust proxy` value
// "loopback, linklocal, uniquelocal".
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128",
	"169.254.0.0/16", "fe80::/10",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
}

var defaultResolver = MustClientIPResolver(nil)

var (
	warnUntrustedForwarded sync.Once
	warnTrustAll           sync.Once
)

// ClientIPResolver resolves the client IP from the socket peer address and
// X-Forwarded-For, believing forwarded entries only from trusted proxies. It
// is safe for concurrent use. A nil *ClientIPResolver uses the default trust
// set.
type ClientIPResolver struct {
	trusted []netip.Prefix
}

// NewClientIPResolver builds a resolver from IPs and CIDR ranges. Nil uses the
// default trust set (127.0.0.0/8, ::1/128, 169.254.0.0/16, fe80::/10,
// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7); an empty non-nil slice
// trusts nothing. It returns an error for an entry that is neither an IP nor a
// CIDR range, and logs a one-time warning when an entry trusts every address
// (0.0.0.0/0 or ::/0).
func NewClientIPResolver(trustedProxies []string) (*ClientIPResolver, error) {
	if trustedProxies == nil {
		trustedProxies = defaultTrustedProxies
	}
	prefixes := make([]netip.Prefix, 0, len(trustedProxies))
	for _, raw := range trustedProxies {
		prefix, err := parseTrustedProxy(raw)
		if err != nil {
			return nil, err
		}
		if prefix.Bits() == 0 {
			warnTrustAll.Do(func() {
				log.Printf("arcis: TrustedProxies contains %s, so every peer is trusted and any client can set its own IP with X-Forwarded-For", prefix)
			})
		}
		prefixes = append(prefixes, prefix)
	}
	return &ClientIPResolver{trusted: prefixes}, nil
}

// MustClientIPResolver is NewClientIPResolver for constructors that cannot
// return an error. It panics with a descriptive message on an invalid entry.
func MustClientIPResolver(trustedProxies []string) *ClientIPResolver {
	resolver, err := NewClientIPResolver(trustedProxies)
	if err != nil {
		panic("arcis: invalid TrustedProxies: " + err.Error())
	}
	return resolver
}

// ClientIP resolves the client IP of r from r.RemoteAddr and its
// X-Forwarded-For headers. It returns "" when no address can be determined.
func (c *ClientIPResolver) ClientIP(r *http.Request) string {
	return c.Resolve(r.RemoteAddr, r.Header.Values("X-Forwarded-For")...)
}

// Resolve returns the normalized client IP for a socket peer address ("ip",
// "ip:port" or "[ipv6]:port") and the X-Forwarded-For header values in the
// order received. It walks from the peer through the forwarded entries right
// to left and stops at the first address that is invalid or untrusted; an
// invalid entry yields the trusted proxy that reported it. The result drops
// any IPv6 zone, unwraps IPv4-mapped IPv6 and is "" when the peer is not a
// valid IP.
func (c *ClientIPResolver) Resolve(peer string, xForwardedFor ...string) string {
	client, ok := parseAddr(peer)
	if !ok {
		return ""
	}
	entries := forwardedEntries(xForwardedFor)
	if len(entries) == 0 {
		return formatAddr(client)
	}
	trusted := c.prefixes()
	if !isTrusted(client, trusted) {
		warnUntrustedForwarded.Do(func() {
			log.Printf("arcis: ignoring X-Forwarded-For from untrusted peer %s; if the app runs behind a proxy, add it to TrustedProxies", formatAddr(client))
		})
		return formatAddr(client)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		addr, ok := parseAddr(entries[i])
		if !ok {
			break
		}
		client = addr
		if !isTrusted(addr, trusted) {
			break
		}
	}
	return formatAddr(client)
}

func (c *ClientIPResolver) prefixes() []netip.Prefix {
	if c == nil {
		return defaultResolver.trusted
	}
	return c.trusted
}

// RateLimitKey turns a resolved client IP into a rate-limit key: IPv4 as is,
// IPv6 grouped to its /56 network ("2001:db8:1234:5600::/56"), and
// UnknownClientKey for "".
func RateLimitKey(ip string) string {
	return IPKey(ip, DefaultIPv6Subnet)
}

// IPKey is the key function behind RateLimitKey (express-rate-limit's
// ipKeyGenerator). IPv4 and IPv4-mapped IPv6 addresses key as the IPv4
// address. An IPv6 address keys as its network written "<network>/<bits>"
// when ipv6Subnet is between 1 and 128, and as the address unchanged
// otherwise (pass 0 for the full address). A value that is not an IP is
// returned unchanged, and "" becomes UnknownClientKey.
func IPKey(ip string, ipv6Subnet int) string {
	if ip == "" {
		return UnknownClientKey
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	if ipv6Subnet < 1 || ipv6Subnet > 128 {
		return ip
	}
	return netip.PrefixFrom(addr.WithZone(""), ipv6Subnet).Masked().String()
}

func parseTrustedProxy(raw string) (netip.Prefix, error) {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP or CIDR range", raw)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP or CIDR range", raw)
	}
	addr = addr.WithZone("").Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// parseAddr accepts "ip", "ip:port" and "[ipv6]:port".
func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr, true
	}
	if addrPort, err := netip.ParseAddrPort(s); err == nil {
		return addrPort.Addr(), true
	}
	return netip.Addr{}, false
}

// forwardedEntries splits X-Forwarded-For values into trimmed, non-empty
// entries in header order.
func forwardedEntries(values []string) []string {
	var entries []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				entries = append(entries, part)
			}
		}
	}
	return entries
}

// isTrusted matches like proxy-addr: IPv4-mapped IPv6 matches IPv4 ranges and
// IPv4 matches IPv6 ranges in its mapped form.
func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	addr = addr.WithZone("").Unmap()
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
		if addr.Is4() && prefix.Addr().Is6() && prefix.Contains(netip.AddrFrom16(addr.As16())) {
			return true
		}
	}
	return false
}

func formatAddr(addr netip.Addr) string {
	return addr.WithZone("").Unmap().String()
}
