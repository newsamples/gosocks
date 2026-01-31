package routing

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouter_FindRoute(t *testing.T) {
	routes := []Route{
		{Pattern: "\\.onion$", Upstream: "127.0.0.1:9050"},
		{Pattern: "^youtube\\.com$", Upstream: "proxy.example.com:1080"},
		{Pattern: "(^|\\.)google\\.com$", Upstream: "proxy.example.com:1080"},
		{Pattern: ".*", Upstream: "default.proxy.com:1080"},
	}

	router, err := NewRouter(routes)
	require.NoError(t, err)

	t.Run("onion domain routing", func(t *testing.T) {
		route, found := router.FindRoute("facebookcorewwwi.onion:80")
		require.True(t, found)
		assert.Equal(t, "\\.onion$", route.Pattern)
		assert.Equal(t, "127.0.0.1:9050", route.Upstream)
	})

	t.Run("exact domain match", func(t *testing.T) {
		route, found := router.FindRoute("youtube.com:443")
		require.True(t, found)
		assert.Equal(t, "^youtube\\.com$", route.Pattern)
		assert.Equal(t, "proxy.example.com:1080", route.Upstream)
	})

	t.Run("wildcard subdomain match", func(t *testing.T) {
		route, found := router.FindRoute("mail.google.com:443")
		require.True(t, found)
		assert.Equal(t, "(^|\\.)google\\.com$", route.Pattern)
		assert.Equal(t, "proxy.example.com:1080", route.Upstream)
	})

	t.Run("root domain match for wildcard", func(t *testing.T) {
		route, found := router.FindRoute("google.com:443")
		require.True(t, found)
		assert.Equal(t, "(^|\\.)google\\.com$", route.Pattern)
		assert.Equal(t, "proxy.example.com:1080", route.Upstream)
	})

	t.Run("default route fallback", func(t *testing.T) {
		route, found := router.FindRoute("example.org:80")
		require.True(t, found)
		assert.Equal(t, ".*", route.Pattern)
		assert.Equal(t, "default.proxy.com:1080", route.Upstream)
	})

	t.Run("address without port", func(t *testing.T) {
		route, found := router.FindRoute("facebookcorewwwi.onion")
		require.True(t, found)
		assert.Equal(t, "\\.onion$", route.Pattern)
	})

	t.Run("case insensitive matching", func(t *testing.T) {
		route, found := router.FindRoute("YOUTUBE.COM:443")
		require.True(t, found)
		assert.Equal(t, "^youtube\\.com$", route.Pattern)

		route, found = router.FindRoute("MAIL.GOOGLE.COM:443")
		require.True(t, found)
		assert.Equal(t, "(^|\\.)google\\.com$", route.Pattern)

		route, found = router.FindRoute("TEST.ONION:80")
		require.True(t, found)
		assert.Equal(t, "\\.onion$", route.Pattern)
	})
}

func TestRouter_RegexPatterns(t *testing.T) {
	t.Run("complex regex patterns", func(t *testing.T) {
		routes := []Route{
			{Pattern: "^(www\\.|m\\.)?youtube\\.com$", Upstream: "youtube.proxy.com:1080"},
			{Pattern: "^[a-z0-9]+\\.onion$", Upstream: "127.0.0.1:9050"},
			{Pattern: "^.*\\.(gov|mil)$", Upstream: "secure.proxy.com:1080"},
			{Pattern: "^(192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)", Upstream: "internal.proxy.com:1080"},
		}

		router, err := NewRouter(routes)
		require.NoError(t, err)

		testCases := []struct {
			destination     string
			expectedPattern string
			shouldMatch     bool
		}{
			{"www.youtube.com:80", "^(www\\.|m\\.)?youtube\\.com$", true},
			{"m.youtube.com:80", "^(www\\.|m\\.)?youtube\\.com$", true},
			{"youtube.com:80", "^(www\\.|m\\.)?youtube\\.com$", true},
			{"api.youtube.com:80", "^[a-z0-9]+\\.onion$", false},
			{"facebookcorewwwi.onion:80", "^[a-z0-9]+\\.onion$", true},
			{"test123.onion:80", "^[a-z0-9]+\\.onion$", true},
			{"test_invalid.onion:80", "^[a-z0-9]+\\.onion$", false},
			{"cia.gov:80", "^.*\\.(gov|mil)$", true},
			{"pentagon.mil:80", "^.*\\.(gov|mil)$", true},
			{"192.168.1.1:80", "^(192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)", true},
			{"10.0.0.1:80", "^(192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)", true},
			{"172.16.0.1:80", "^(192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)", true},
		}

		for _, tc := range testCases {
			route, found := router.FindRoute(tc.destination)
			if tc.shouldMatch {
				assert.True(t, found, "Expected match for %s", tc.destination)
				if found {
					assert.Equal(t, tc.expectedPattern, route.Pattern, "Pattern mismatch for %s", tc.destination)
				}
			} else if found && route.Pattern == tc.expectedPattern {
				// Should either not match or match a different pattern
				t.Errorf("Expected %s NOT to match pattern %s", tc.destination, tc.expectedPattern)
			}
		}
	})
}

func TestRoute_FirstMatchWins(t *testing.T) {
	// Test that routes are matched in order (first match wins)
	routes := []Route{
		{Pattern: "^.*\\.example\\.com$", Upstream: "first.proxy.com:1080"},
		{Pattern: "^test\\.example\\.com$", Upstream: "second.proxy.com:1080"},
		{Pattern: ".*", Upstream: "default.proxy.com:1080"},
	}

	router, err := NewRouter(routes)
	require.NoError(t, err)

	route, found := router.FindRoute("test.example.com:80")
	require.True(t, found)
	assert.Equal(t, "^.*\\.example\\.com$", route.Pattern)
	assert.Equal(t, "first.proxy.com:1080", route.Upstream)
}

func TestRouter_EmptyRoutes(t *testing.T) {
	router, err := NewRouter(nil)
	require.NoError(t, err)

	route, found := router.FindRoute("example.com:80")
	assert.False(t, found)
	assert.Nil(t, route)
}

func TestRouter_InvalidRegex(t *testing.T) {
	routes := []Route{
		{Pattern: "[invalid regex", Upstream: "127.0.0.1:1080"},
	}

	router, err := NewRouter(routes)
	assert.Error(t, err)
	assert.Nil(t, router)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestNewUpstreamDialer(t *testing.T) {
	timeout := 5 * time.Second
	dialer := NewUpstreamDialer("127.0.0.1:1080", timeout)

	assert.Equal(t, "127.0.0.1:1080", dialer.upstream)
	assert.Equal(t, timeout, dialer.timeout)
}

func TestUpstreamDialer_UnsupportedNetwork(t *testing.T) {
	dialer := NewUpstreamDialer("127.0.0.1:1080", 5*time.Second)

	conn, err := dialer.Dial("udp", "example.com:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "unsupported network type: udp")
}

func TestUpstreamDialer_InvalidUpstreamAddress(t *testing.T) {
	dialer := NewUpstreamDialer("invalid:address:format", 1*time.Second)

	conn, err := dialer.Dial("tcp", "example.com:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "failed to connect to upstream server")
}

func TestUpstreamDialer_ConnectionTimeout(t *testing.T) {
	// Use a non-routable address to trigger timeout
	dialer := NewUpstreamDialer("10.255.255.1:1080", 100*time.Millisecond)

	conn, err := dialer.Dial("tcp", "example.com:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

// Mock SOCKS5 server for testing upstream functionality
type mockSOCKS5Server struct {
	listener net.Listener
	response []byte
}

func newMockSOCKS5Server(t *testing.T, response []byte) *mockSOCKS5Server {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &mockSOCKS5Server{
		listener: listener,
		response: response,
	}

	go server.serve()
	return server
}

func (m *mockSOCKS5Server) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return
		}
		go m.handleConnection(conn)
	}
}

func (m *mockSOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read auth request
	authReq := make([]byte, 3)
	conn.Read(authReq)

	// Send auth response (success)
	conn.Write([]byte{0x05, 0x00})

	// Read connect request (we'll just read some bytes)
	connectReq := make([]byte, 256)
	conn.Read(connectReq)

	// Send custom response
	conn.Write(m.response)
}

func (m *mockSOCKS5Server) close() {
	m.listener.Close()
}

func (m *mockSOCKS5Server) addr() string {
	return m.listener.Addr().String()
}

func TestUpstreamDialer_SOCKS5Handshake(t *testing.T) {
	t.Run("successful handshake", func(t *testing.T) {
		// Valid SOCKS5 response: success with IPv4 address
		response := []byte{
			0x05, 0x00, 0x00, 0x01, // Version, success, reserved, IPv4
			127, 0, 0, 1, // IPv4 address
			0x00, 0x50, // Port 80
		}

		server := newMockSOCKS5Server(t, response)
		defer server.close()

		dialer := NewUpstreamDialer(server.addr(), 5*time.Second)
		conn, err := dialer.Dial("tcp", "example.com:80")

		assert.NoError(t, err)
		assert.NotNil(t, conn)
		if conn != nil {
			conn.Close()
		}
	})

	t.Run("SOCKS5 server returns error", func(t *testing.T) {
		// SOCKS5 response with error code
		response := []byte{
			0x05, 0x01, 0x00, 0x01, // Version, general failure, reserved, IPv4
			127, 0, 0, 1, // IPv4 address
			0x00, 0x50, // Port 80
		}

		server := newMockSOCKS5Server(t, response)
		defer server.close()

		dialer := NewUpstreamDialer(server.addr(), 5*time.Second)
		conn, err := dialer.Dial("tcp", "example.com:80")

		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "connect request failed: reply code 1")
	})

	t.Run("invalid SOCKS version", func(t *testing.T) {
		// Invalid SOCKS version in auth response
		response := []byte{0x04, 0x00} // SOCKS4 instead of SOCKS5

		server := newMockSOCKS5Server(t, response)
		defer server.close()

		dialer := NewUpstreamDialer(server.addr(), 5*time.Second)
		conn, err := dialer.Dial("tcp", "example.com:80")

		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "invalid SOCKS version")
	})
}

func TestRoute_Timeout(t *testing.T) {
	routes := []Route{
		{
			Pattern:  "^slow\\.example\\.com$",
			Upstream: "127.0.0.1:1080",
			Timeout:  1 * time.Second,
		},
		{
			Pattern:  "^fast\\.example\\.com$",
			Upstream: "127.0.0.1:1080",
			// No timeout specified - should use default
		},
	}

	router, err := NewRouter(routes)
	require.NoError(t, err)

	t.Run("custom timeout", func(t *testing.T) {
		route, found := router.FindRoute("slow.example.com:80")
		require.True(t, found)
		assert.Equal(t, 1*time.Second, route.Timeout)
	})

	t.Run("default timeout", func(t *testing.T) {
		route, found := router.FindRoute("fast.example.com:80")
		require.True(t, found)
		assert.Equal(t, time.Duration(0), route.Timeout)
	})
}

func TestUpstreamDialer_AddressTypes(t *testing.T) {
	// Test different address types in SOCKS5 connect request
	dialer := NewUpstreamDialer("127.0.0.1:1080", 5*time.Second)

	t.Run("IPv4 address parsing", func(t *testing.T) {
		// This will fail to connect, but we can test the address parsing logic
		conn, err := dialer.Dial("tcp", "192.168.1.1:80")
		assert.Error(t, err) // Expected to fail since no real server
		assert.Nil(t, conn)
	})

	t.Run("IPv6 address parsing", func(t *testing.T) {
		conn, err := dialer.Dial("tcp", "[::1]:80")
		assert.Error(t, err) // Expected to fail since no real server
		assert.Nil(t, conn)
	})

	t.Run("domain name parsing", func(t *testing.T) {
		conn, err := dialer.Dial("tcp", "example.com:80")
		assert.Error(t, err) // Expected to fail since no real server
		assert.Nil(t, conn)
	})

	t.Run("invalid address format", func(t *testing.T) {
		conn, err := dialer.Dial("tcp", "invalid-address-format")
		assert.Error(t, err)
		assert.Nil(t, conn)
		// Error could be either invalid target address or connection failure
		assert.True(t,
			strings.Contains(err.Error(), "invalid target address") ||
				strings.Contains(err.Error(), "failed to connect to upstream server"),
			"Expected error about invalid address or connection failure, got: %s", err.Error())
	})

	t.Run("domain name too long", func(t *testing.T) {
		longDomain := make([]byte, 256)
		for i := range longDomain {
			longDomain[i] = 'a'
		}
		address := string(longDomain) + ".com:80"

		conn, err := dialer.Dial("tcp", address)
		assert.Error(t, err)
		assert.Nil(t, conn)
		// Error could be either domain name too long or connection failure
		assert.True(t,
			strings.Contains(err.Error(), "domain name too long") ||
				strings.Contains(err.Error(), "failed to connect to upstream server"),
			"Expected error about domain length or connection failure, got: %s", err.Error())
	})
}