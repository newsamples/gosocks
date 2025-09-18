package socks5

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGateway(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		config := &GatewayConfig{
			EnableIPv4ToIPv6: true,
			EnableIPv6ToIPv4: true,
			IPv6Prefix:       "2001:db8::",
			IPv4Subnet:       "192.168.1.0/24",
		}

		gw, err := NewGateway(config)
		require.NoError(t, err)
		assert.NotNil(t, gw)
		assert.Equal(t, config, gw.config)
	})

	t.Run("invalid IPv6 prefix", func(t *testing.T) {
		config := &GatewayConfig{
			EnableIPv4ToIPv6: true,
			IPv6Prefix:       "invalid",
		}

		_, err := NewGateway(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IPv6 prefix")
	})

	t.Run("invalid IPv4 subnet", func(t *testing.T) {
		config := &GatewayConfig{
			EnableIPv6ToIPv4: true,
			IPv4Subnet:       "invalid",
		}

		_, err := NewGateway(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IPv4 subnet")
	})
}

func TestGateway_TranslateAddress(t *testing.T) {
	config := &GatewayConfig{
		EnableIPv4ToIPv6: true,
		EnableIPv6ToIPv4: true,
		IPv6Prefix:       "2001:db8::",
		IPv4Subnet:       "192.168.1.0/24",
	}

	gw, err := NewGateway(config)
	require.NoError(t, err)

	t.Run("IPv4 to IPv6 translation", func(t *testing.T) {
		addr := &Address{
			Type: AddressTypeIPv4,
			IP:   net.ParseIP("192.168.1.1"),
			Port: 80,
		}

		translated, err := gw.TranslateAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, translated.Type, AddressTypeIPv6)
		assert.Equal(t, translated.Port, uint16(80))
	})

	t.Run("IPv6 to IPv4 translation", func(t *testing.T) {
		ipv6 := make(net.IP, 16)
		ipv6[10] = 0xff
		ipv6[11] = 0xff
		copy(ipv6[12:], net.ParseIP("192.168.1.1").To4())

		addr := &Address{
			Type: AddressTypeIPv6,
			IP:   ipv6,
			Port: 80,
		}

		translated, err := gw.TranslateAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, translated.Type, AddressTypeIPv4)
		assert.Equal(t, translated.IP.String(), "192.168.1.1")
		assert.Equal(t, translated.Port, uint16(80))
	})

	t.Run("no translation needed", func(t *testing.T) {
		addr := &Address{
			Type: AddressTypeDomain,
			Host: "example.com",
			Port: 80,
		}

		translated, err := gw.TranslateAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, addr, translated)
	})
}

func TestGateway_isIPv4MappedIPv6(t *testing.T) {
	gw, _ := NewGateway(&GatewayConfig{})

	t.Run("valid IPv4-mapped IPv6", func(t *testing.T) {
		ip := make(net.IP, 16)
		ip[10] = 0xff
		ip[11] = 0xff
		copy(ip[12:], net.ParseIP("192.168.1.1").To4())

		assert.True(t, gw.isIPv4MappedIPv6(ip))
	})

	t.Run("regular IPv6", func(t *testing.T) {
		ip := net.ParseIP("2001:db8::1")
		assert.False(t, gw.isIPv4MappedIPv6(ip))
	})

	t.Run("invalid length", func(t *testing.T) {
		ip := net.ParseIP("192.168.1.1").To4()
		assert.False(t, gw.isIPv4MappedIPv6(ip))
	})
}

func TestGateway_ResolveAddress(t *testing.T) {
	config := &GatewayConfig{
		EnableIPv4ToIPv6: true,
		IPv6Prefix:       "2001:db8::",
	}

	gw, err := NewGateway(config)
	require.NoError(t, err)

	t.Run("IPv4 address", func(t *testing.T) {
		addr := &Address{
			Type: AddressTypeIPv4,
			IP:   net.ParseIP("192.168.1.1"),
			Port: 80,
		}

		result, err := gw.ResolveAddress(addr)
		require.NoError(t, err)
		assert.Contains(t, result, "80")
	})

	t.Run("domain address", func(t *testing.T) {
		addr := &Address{
			Type: AddressTypeDomain,
			Host: "example.com",
			Port: 80,
		}

		result, err := gw.ResolveAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, "example.com:80", result)
	})

	t.Run("unsupported address type", func(t *testing.T) {
		addr := &Address{
			Type: 0xFF,
			Port: 80,
		}

		_, err := gw.ResolveAddress(addr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported address type")
	})
}

func TestGateway_SupportsDualStack(t *testing.T) {
	t.Run("dual stack enabled", func(t *testing.T) {
		config := &GatewayConfig{
			EnableIPv4ToIPv6: true,
			EnableIPv6ToIPv4: false,
		}

		gw, _ := NewGateway(config)
		assert.True(t, gw.SupportsDualStack())
	})

	t.Run("dual stack disabled", func(t *testing.T) {
		config := &GatewayConfig{
			EnableIPv4ToIPv6: false,
			EnableIPv6ToIPv4: false,
		}

		gw, _ := NewGateway(config)
		assert.False(t, gw.SupportsDualStack())
	})
}

func TestGateway_GetPreferredNetwork(t *testing.T) {
	config := &GatewayConfig{
		EnableIPv4ToIPv6: true,
		EnableIPv6ToIPv4: true,
	}

	gw, _ := NewGateway(config)

	t.Run("IPv4 target", func(t *testing.T) {
		network := gw.GetPreferredNetwork("192.168.1.1:80")
		assert.Equal(t, "tcp6", network)
	})

	t.Run("IPv6 target", func(t *testing.T) {
		network := gw.GetPreferredNetwork("[2001:db8::1]:80")
		assert.Equal(t, "tcp4", network)
	})

	t.Run("domain target", func(t *testing.T) {
		network := gw.GetPreferredNetwork("example.com:80")
		assert.Equal(t, "tcp", network)
	})

	t.Run("invalid target", func(t *testing.T) {
		network := gw.GetPreferredNetwork("invalid")
		assert.Equal(t, "tcp", network)
	})
}

func TestGateway_IsIPv6Address(t *testing.T) {
	gw, _ := NewGateway(&GatewayConfig{})

	tests := []struct {
		addr     string
		expected bool
	}{
		{"192.168.1.1", false},
		{"2001:db8::1", true},
		{"::1", true},
		{"example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			result := gw.IsIPv6Address(tt.addr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGateway_IsIPv4Address(t *testing.T) {
	gw, _ := NewGateway(&GatewayConfig{})

	tests := []struct {
		addr     string
		expected bool
	}{
		{"192.168.1.1", true},
		{"2001:db8::1", false},
		{"invalid", false},
		{"example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			result := gw.IsIPv4Address(tt.addr)
			assert.Equal(t, tt.expected, result)
		})
	}
}
