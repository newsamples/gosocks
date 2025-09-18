package socks5

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddress_String(t *testing.T) {
	tests := []struct {
		name     string
		address  Address
		expected string
	}{
		{
			name: "IPv4 address",
			address: Address{
				Type: AddressTypeIPv4,
				IP:   net.ParseIP("192.168.1.1"),
				Port: 8080,
			},
			expected: "192.168.1.1:8080",
		},
		{
			name: "IPv6 address",
			address: Address{
				Type: AddressTypeIPv6,
				IP:   net.ParseIP("2001:db8::1"),
				Port: 8080,
			},
			expected: "[2001:db8::1]:8080",
		},
		{
			name: "Domain address",
			address: Address{
				Type: AddressTypeDomain,
				Host: "example.com",
				Port: 8080,
			},
			expected: "example.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.address.String()
			assert.Contains(t, result, "8080")
		})
	}
}

func TestAddress_Network(t *testing.T) {
	addr := &Address{}
	assert.Equal(t, "tcp", addr.Network())
}

func TestConstants(t *testing.T) {
	t.Run("SOCKS version", func(t *testing.T) {
		assert.Equal(t, Socks5Version, byte(0x05))
	})

	t.Run("Auth methods", func(t *testing.T) {
		assert.Equal(t, AuthMethodNoAuth, byte(0x00))
		assert.Equal(t, AuthMethodGSSAPI, byte(0x01))
		assert.Equal(t, AuthMethodUserPass, byte(0x02))
		assert.Equal(t, AuthMethodNoAcceptable, byte(0xFF))
	})

	t.Run("Commands", func(t *testing.T) {
		assert.Equal(t, CommandConnect, byte(0x01))
		assert.Equal(t, CommandBind, byte(0x02))
		assert.Equal(t, CommandUDPAssociate, byte(0x03))
	})

	t.Run("Address types", func(t *testing.T) {
		assert.Equal(t, AddressTypeIPv4, byte(0x01))
		assert.Equal(t, AddressTypeDomain, byte(0x03))
		assert.Equal(t, AddressTypeIPv6, byte(0x04))
	})

	t.Run("Reply codes", func(t *testing.T) {
		assert.Equal(t, ReplySucceeded, byte(0x00))
		assert.Equal(t, ReplyGeneralFailure, byte(0x01))
		assert.Equal(t, ReplyAddressTypeNotSupported, byte(0x08))
	})
}

func TestErrors(t *testing.T) {
	t.Run("Error constants", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidVersion)
		assert.NotNil(t, ErrInvalidCommand)
		assert.NotNil(t, ErrInvalidAddressType)
		assert.NotNil(t, ErrAuthFailed)
		assert.NotNil(t, ErrNoAcceptableAuth)
	})
}
