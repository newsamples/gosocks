package routing

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Route defines a routing rule that matches certain destination patterns
// and forwards them to specific upstream servers
type Route struct {
	// Pattern is the regex pattern for matching destinations
	// Examples:
	// - Exact domain: "^example\\.com$"
	// - TLD suffix: "\\.onion$"
	// - Subdomain wildcard: "^.*\\.google\\.com$"
	// - Catch-all: ".*"
	Pattern string

	// Upstream is the upstream SOCKS5 server address
	// Format: "host:port" (e.g., "127.0.0.1:9050", "proxy.example.com:1080")
	Upstream string

	// Timeout for connections to this upstream server
	// If zero, uses the server's default ConnectTimeout
	Timeout time.Duration

	// compiled regex pattern (internal use)
	regex *regexp.Regexp
}

// Router manages routing rules and upstream connections
type Router struct {
	routes []Route
}

// NewRouter creates a new router with the given routes
func NewRouter(routes []Route) (*Router, error) {
	// Compile all regex patterns
	for i := range routes {
		compiled, err := regexp.Compile(routes[i].Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern '%s': %w", routes[i].Pattern, err)
		}
		routes[i].regex = compiled
	}

	return &Router{
		routes: routes,
	}, nil
}

// FindRoute finds the first matching route for the given destination
// Returns the route and true if found, or nil and false if no match
func (r *Router) FindRoute(destination string) (*Route, bool) {
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		// If destination doesn't have port, use as-is
		host = destination
	}

	// Convert to lowercase for case-insensitive matching
	host = strings.ToLower(host)

	for i := range r.routes {
		route := &r.routes[i]
		if route.regex.MatchString(host) {
			return route, true
		}
	}

	return nil, false
}

// UpstreamDialer creates network connections through upstream SOCKS5 servers
type UpstreamDialer struct {
	upstream string
	timeout  time.Duration
}

// NewUpstreamDialer creates a new upstream dialer for the given server
func NewUpstreamDialer(upstream string, timeout time.Duration) *UpstreamDialer {
	return &UpstreamDialer{
		upstream: upstream,
		timeout:  timeout,
	}
}

// Dial connects to the target address through the upstream SOCKS5 server
func (d *UpstreamDialer) Dial(network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}

	// Connect to upstream SOCKS5 server
	upstreamConn, err := net.DialTimeout("tcp", d.upstream, d.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream server %s: %w", d.upstream, err)
	}

	// Perform SOCKS5 handshake and connect to target
	conn, err := d.performSOCKS5Handshake(upstreamConn, address)
	if err != nil {
		upstreamConn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed with %s: %w", d.upstream, err)
	}

	return conn, nil
}

// performSOCKS5Handshake performs the SOCKS5 client handshake
func (d *UpstreamDialer) performSOCKS5Handshake(conn net.Conn, targetAddr string) (net.Conn, error) {
	// Set timeout for handshake
	if d.timeout > 0 {
		conn.SetDeadline(time.Now().Add(d.timeout))
	}

	// Step 1: Send authentication request (no auth)
	authReq := []byte{0x05, 0x01, 0x00} // Version 5, 1 method, no auth
	if _, err := conn.Write(authReq); err != nil {
		return nil, fmt.Errorf("failed to send auth request: %w", err)
	}

	// Step 2: Read authentication response
	authResp := make([]byte, 2)
	if _, err := conn.Read(authResp); err != nil {
		return nil, fmt.Errorf("failed to read auth response: %w", err)
	}

	if authResp[0] != 0x05 {
		return nil, fmt.Errorf("invalid SOCKS version: %d", authResp[0])
	}
	if authResp[1] != 0x00 {
		return nil, fmt.Errorf("authentication failed: method %d", authResp[1])
	}

	// Step 3: Send connect request
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	connectReq := []byte{0x05, 0x01, 0x00} // Version, CONNECT command, reserved

	// Add address type and address
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			connectReq = append(connectReq, 0x01) // IPv4 address type
			connectReq = append(connectReq, ip4...)
		} else {
			// IPv6
			connectReq = append(connectReq, 0x04) // IPv6 address type
			connectReq = append(connectReq, ip...)
		}
	} else {
		// Domain name
		if len(host) > 255 {
			return nil, fmt.Errorf("domain name too long: %d", len(host))
		}
		connectReq = append(connectReq, 0x03)            // Domain name type
		connectReq = append(connectReq, byte(len(host))) // Domain length
		connectReq = append(connectReq, []byte(host)...)
	}

	// Add port (2 bytes, big endian)
	connectReq = append(connectReq, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(connectReq); err != nil {
		return nil, fmt.Errorf("failed to send connect request: %w", err)
	}

	// Step 4: Read connect response
	connectResp := make([]byte, 4)
	if _, err := conn.Read(connectResp); err != nil {
		return nil, fmt.Errorf("failed to read connect response: %w", err)
	}

	if connectResp[0] != 0x05 {
		return nil, fmt.Errorf("invalid SOCKS version in response: %d", connectResp[0])
	}
	if connectResp[1] != 0x00 {
		return nil, fmt.Errorf("connect request failed: reply code %d", connectResp[1])
	}

	// Step 5: Read address information from response
	addrType := connectResp[3]
	var addrLen int
	switch addrType {
	case 0x01: // IPv4
		addrLen = 4
	case 0x03: // Domain name
		domainLenByte := make([]byte, 1)
		if _, err := conn.Read(domainLenByte); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		addrLen = int(domainLenByte[0])
	case 0x04: // IPv6
		addrLen = 16
	default:
		return nil, fmt.Errorf("unsupported address type: %d", addrType)
	}

	// Read address and port
	addrAndPort := make([]byte, addrLen+2) // address + 2 bytes for port
	if _, err := conn.Read(addrAndPort); err != nil {
		return nil, fmt.Errorf("failed to read address and port: %w", err)
	}

	// Clear deadline after successful handshake
	conn.SetDeadline(time.Time{})

	return conn, nil
}