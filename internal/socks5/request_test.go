package socks5

import (
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_handleRequest(t *testing.T) {
	config := &Config{
		BindAddress: "127.0.0.1:0",
		Logger:      logrus.New(),
	}
	server, err := NewServer(config)
	require.NoError(t, err)

	t.Run("invalid version", func(t *testing.T) {
		data := []byte{
			0x04, // wrong version
			0x01, 0x00, 0x01,
			192, 168, 1, 1,
			0x00, 0x50,
		}
		conn := newMockConn(data)

		err := server.handleRequest(conn)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidVersion, err)
	})

	t.Run("unsupported command", func(t *testing.T) {
		data := []byte{
			0x05, // version
			0x04, // unsupported command
			0x00, 0x01,
			192, 168, 1, 1,
			0x00, 0x50,
		}
		conn := newMockConn(data)

		err := server.handleRequest(conn)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidCommand, err)
	})

	t.Run("BIND command - invalid address", func(t *testing.T) {
		data := []byte{
			0x05, // version
			0x02, // BIND command
			0x00, 0x01,
			192, 168, 1, // Invalid IPv4 (too short)
			0x00, 0x50,
		}
		conn := newMockConn(data)

		err := server.handleRequest(conn)
		assert.Error(t, err)
		// Since BIND is now implemented, it tries to parse address and may get different errors
		assert.NotNil(t, err)
	})

	t.Run("UDP ASSOCIATE command - invalid address", func(t *testing.T) {
		data := []byte{
			0x05, // version
			0x03, // UDP ASSOCIATE command
			0x00, 0x01,
			192, 168, 1, // Invalid IPv4 (too short)
			0x00, 0x50,
		}
		conn := newMockConn(data)

		err := server.handleRequest(conn)
		assert.Error(t, err)
		// Since UDP ASSOCIATE is now implemented, it tries to parse address
		assert.NotNil(t, err)
	})
}

func TestServer_resolveAddress(t *testing.T) {
	config := &Config{
		BindAddress: "127.0.0.1:0",
		IPv6Gateway: false,
	}
	server, err := NewServer(config)
	require.NoError(t, err)

	t.Run("IPv4 address", func(t *testing.T) {
		addr := &Address{
			Type: AddressTypeIPv4,
			IP:   net.ParseIP("192.168.1.1"),
			Port: 80,
		}

		result := server.resolveAddress(addr)
		assert.Equal(t, "192.168.1.1:80", result)
	})

	t.Run("IPv6 address", func(t *testing.T) {
		addr := &Address{
			Type: AddressTypeIPv6,
			IP:   net.ParseIP("2001:db8::1"),
			Port: 443,
		}

		result := server.resolveAddress(addr)
		assert.Equal(t, "[2001:db8::1]:443", result)
	})

	t.Run("domain address", func(t *testing.T) {
		addr := &Address{
			Type: AddressTypeDomain,
			Host: "example.com",
			Port: 80,
		}

		result := server.resolveAddress(addr)
		assert.Equal(t, "example.com:80", result)
	})
}

func TestServer_resolveAddressWithIPv6Gateway(t *testing.T) {
	config := &Config{
		BindAddress: "127.0.0.1:0",
		IPv6Gateway: true,
	}
	server, err := NewServer(config)
	require.NoError(t, err)

	t.Run("IPv4 with gateway enabled", func(t *testing.T) {
		addr := &Address{
			Type: AddressTypeIPv4,
			IP:   net.ParseIP("192.168.1.1"),
			Port: 80,
		}

		result := server.resolveAddress(addr)
		// Basic functionality test - just ensure it returns a valid address
		assert.Contains(t, result, "80")
		assert.Contains(t, result, "192.168.1.1")
	})
}

func TestServer_dialTarget(t *testing.T) {
	config := &Config{
		BindAddress:    "127.0.0.1:0",
		ConnectTimeout: 1 * time.Second,
	}
	server, err := NewServer(config)
	require.NoError(t, err)

	t.Run("invalid address", func(t *testing.T) {
		_, err := server.dialTarget("invalid:address:format")
		assert.Error(t, err)
	})

	t.Run("connection timeout", func(t *testing.T) {
		// Use a non-routable address to force timeout
		_, err := server.dialTarget("10.255.255.1:12345")
		assert.Error(t, err)
	})
}

func TestServer_sendErrorResponse(t *testing.T) {
	server := &Server{}

	t.Run("send error response", func(t *testing.T) {
		conn := newMockConn(nil)
		server.sendErrorResponse(conn, ReplyConnectionRefused)

		expected := []byte{0x05, ReplyConnectionRefused, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		assert.Equal(t, expected, conn.writeData)
	})
}

func TestServer_handleBind(t *testing.T) {
	config := &Config{
		BindAddress:    "127.0.0.1:0",
		ConnectTimeout: 1 * time.Second,
		Logger:         logrus.New(),
	}
	server, err := NewServer(config)
	require.NoError(t, err)

	t.Run("successful bind with timeout", func(t *testing.T) {
		req := &ConnectRequest{
			Version:     Socks5Version,
			Command:     CommandBind,
			AddressType: AddressTypeIPv4,
			Address:     []byte{127, 0, 0, 1},
			Port:        80,
		}

		conn := newMockConn(nil)

		// This should timeout waiting for incoming connection and return an error
		err := server.handleBind(conn, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to accept bind connection")

		// Verify that the first response was sent (bound address)
		conn.mutex.Lock()
		hasWrittenData := len(conn.writeData) >= 10 // Basic SOCKS response is 10 bytes
		var firstByte, secondByte byte
		if len(conn.writeData) >= 2 {
			firstByte = conn.writeData[0]
			secondByte = conn.writeData[1]
		}
		conn.mutex.Unlock()

		assert.True(t, hasWrittenData, "Expected response data to be written")
		if hasWrittenData {
			assert.Equal(t, byte(0x05), firstByte, "Expected SOCKS version 5")
			assert.Equal(t, ReplySucceeded, secondByte, "Expected success reply")
		}
	})

	t.Run("invalid address type", func(t *testing.T) {
		req := &ConnectRequest{
			Version:     Socks5Version,
			Command:     CommandBind,
			AddressType: 0xFF, // Invalid address type
			Address:     []byte{127, 0, 0, 1},
			Port:        80,
		}

		conn := newMockConn(nil)
		err := server.handleBind(conn, req)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidAddressType, err)

		// Check error response was sent
		assert.NotEmpty(t, conn.writeData)
		assert.Equal(t, byte(0x05), conn.writeData[0]) // SOCKS version
		assert.Equal(t, ReplyAddressTypeNotSupported, conn.writeData[1])
	})
}

func TestServer_validateBindConnection(t *testing.T) {
	server := &Server{}

	t.Run("valid IPv4 match", func(t *testing.T) {
		expectedAddr := &Address{
			Type: AddressTypeIPv4,
			IP:   net.ParseIP("192.168.1.1"),
			Port: 80,
		}

		mockAddr := &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 12345,
		}

		result := server.validateBindConnection(expectedAddr, mockAddr)
		assert.True(t, result)
	})

	t.Run("invalid IPv4 mismatch", func(t *testing.T) {
		expectedAddr := &Address{
			Type: AddressTypeIPv4,
			IP:   net.ParseIP("192.168.1.1"),
			Port: 80,
		}

		mockAddr := &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.2"),
			Port: 12345,
		}

		result := server.validateBindConnection(expectedAddr, mockAddr)
		assert.False(t, result)
	})

	t.Run("valid IPv6 match", func(t *testing.T) {
		expectedAddr := &Address{
			Type: AddressTypeIPv6,
			IP:   net.ParseIP("::1"),
			Port: 80,
		}

		mockAddr := &net.TCPAddr{
			IP:   net.ParseIP("::1"),
			Port: 12345,
		}

		result := server.validateBindConnection(expectedAddr, mockAddr)
		assert.True(t, result)
	})

	t.Run("domain address - localhost", func(t *testing.T) {
		expectedAddr := &Address{
			Type: AddressTypeDomain,
			Host: "localhost",
			Port: 80,
		}

		mockAddr := &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 12345,
		}

		result := server.validateBindConnection(expectedAddr, mockAddr)
		assert.True(t, result)
	})

	t.Run("invalid incoming address format", func(t *testing.T) {
		expectedAddr := &Address{
			Type: AddressTypeIPv4,
			IP:   net.ParseIP("192.168.1.1"),
			Port: 80,
		}

		// Mock an address that will cause SplitHostPort to fail
		mockAddr := &mockInvalidAddr{}

		result := server.validateBindConnection(expectedAddr, mockAddr)
		assert.False(t, result)
	})
}

type mockInvalidAddr struct{}

func (m *mockInvalidAddr) Network() string { return "tcp" }
func (m *mockInvalidAddr) String() string  { return "invalid-address-format" }

func TestServer_handleUDPAssociate(t *testing.T) {
	config := &Config{
		BindAddress:    "127.0.0.1:0",
		ConnectTimeout: 1 * time.Second,
		Logger:         logrus.New(),
	}
	server, err := NewServer(config)
	require.NoError(t, err)

	t.Run("basic UDP associate setup", func(t *testing.T) {
		req := &ConnectRequest{
			Version:     Socks5Version,
			Command:     CommandUDPAssociate,
			AddressType: AddressTypeIPv4,
			Address:     []byte{0, 0, 0, 0}, // Any address
			Port:        0,                  // Any port
		}

		conn := newMockConn(nil)

		// This should complete quickly since the mockConn will return EOF on read
		err := server.handleUDPAssociate(conn, req)
		assert.Error(t, err) // Expected to fail on TCP connection read

		// Check that success response was sent
		conn.mutex.Lock()
		hasWrittenData := len(conn.writeData) >= 10 // Basic SOCKS response is 10 bytes
		var firstByte, secondByte byte
		if len(conn.writeData) >= 2 {
			firstByte = conn.writeData[0]
			secondByte = conn.writeData[1]
		}
		conn.mutex.Unlock()

		assert.True(t, hasWrittenData, "Expected response data to be written")
		if hasWrittenData {
			assert.Equal(t, byte(0x05), firstByte, "Expected SOCKS version 5")
			assert.Equal(t, ReplySucceeded, secondByte, "Expected success reply")
		}
	})

	t.Run("invalid address type", func(t *testing.T) {
		req := &ConnectRequest{
			Version:     Socks5Version,
			Command:     CommandUDPAssociate,
			AddressType: 0xFF, // Invalid address type
			Address:     []byte{127, 0, 0, 1},
			Port:        0,
		}

		conn := newMockConn(nil)
		err := server.handleUDPAssociate(conn, req)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidAddressType, err)

		// Check error response was sent
		assert.NotEmpty(t, conn.writeData)
		assert.Equal(t, byte(0x05), conn.writeData[0]) // SOCKS version
		assert.Equal(t, ReplyAddressTypeNotSupported, conn.writeData[1])
	})
}

func TestServer_parseUDPHeader(t *testing.T) {
	server := &Server{}

	t.Run("valid IPv4 UDP header", func(t *testing.T) {
		data := []byte{
			0x00, 0x00, // Reserved
			0x00,            // Fragment
			AddressTypeIPv4, // Address type
			192, 168, 1, 1,  // IPv4 address
			0x00, 0x50, // Port 80
			0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
		}

		header, err := server.parseUDPHeader(data)
		require.NoError(t, err)
		assert.Equal(t, uint16(0), header.Reserved)
		assert.Equal(t, byte(0), header.Fragment)
		assert.Equal(t, AddressTypeIPv4, header.AddressType)
		assert.Equal(t, []byte{192, 168, 1, 1}, header.Address)
		assert.Equal(t, uint16(80), header.Port)
		assert.Equal(t, []byte("Hello"), header.Data)
	})

	t.Run("valid domain UDP header", func(t *testing.T) {
		domain := "example.com"
		data := []byte{
			0x00, 0x00, // Reserved
			0x00,              // Fragment
			AddressTypeDomain, // Address type
			byte(len(domain)), // Domain length
		}
		data = append(data, []byte(domain)...) // Domain
		data = append(data, 0x01, 0xBB)        // Port 443
		data = append(data, []byte("Test")...) // Data

		header, err := server.parseUDPHeader(data)
		require.NoError(t, err)
		assert.Equal(t, AddressTypeDomain, header.AddressType)
		assert.Equal(t, []byte(domain), header.Address)
		assert.Equal(t, uint16(443), header.Port)
		assert.Equal(t, []byte("Test"), header.Data)
	})

	t.Run("fragmented packet error", func(t *testing.T) {
		data := []byte{
			0x00, 0x00, // Reserved
			0x01, // Fragment (non-zero)
			AddressTypeIPv4,
			192, 168, 1, 1,
			0x00, 0x50,
		}

		_, err := server.parseUDPHeader(data)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fragmented UDP packets not supported")
	})

	t.Run("header too short", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00} // Only 3 bytes

		_, err := server.parseUDPHeader(data)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "UDP header too short")
	})

	t.Run("invalid address type", func(t *testing.T) {
		data := []byte{
			0x00, 0x00, // Reserved
			0x00, // Fragment
			0xFF, // Invalid address type
			192, 168, 1, 1,
			0x00, 0x50,
		}

		_, err := server.parseUDPHeader(data)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported address type")
	})
}

func TestServer_serializeUDPHeader(t *testing.T) {
	server := &Server{}

	t.Run("serialize IPv4 header", func(t *testing.T) {
		header := &UDPHeader{
			Reserved:    0,
			Fragment:    0,
			AddressType: AddressTypeIPv4,
			Address:     []byte{192, 168, 1, 1},
			Port:        80,
			Data:        []byte("Hello"),
		}

		data := server.serializeUDPHeader(header)
		expected := []byte{
			0x00, 0x00, 0x00, // Reserved and Fragment
			AddressTypeIPv4, // Address type
			192, 168, 1, 1,  // IPv4 address
			0x00, 0x50, // Port 80
			0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
		}

		assert.Equal(t, expected, data)
	})

	t.Run("serialize domain header", func(t *testing.T) {
		domain := "test.com"
		header := &UDPHeader{
			Reserved:    0,
			Fragment:    0,
			AddressType: AddressTypeDomain,
			Address:     []byte(domain),
			Port:        443,
			Data:        []byte("Data"),
		}

		data := server.serializeUDPHeader(header)
		expected := []byte{
			0x00, 0x00, 0x00, // Reserved and Fragment
			AddressTypeDomain, // Address type
			byte(len(domain)), // Domain length
		}
		expected = append(expected, []byte(domain)...) // Domain
		expected = append(expected, 0x01, 0xBB)        // Port 443
		expected = append(expected, []byte("Data")...) // Data

		assert.Equal(t, expected, data)
	})
}
