package socks5

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockConn struct {
	*bytes.Buffer
	readData  []byte
	writeData []byte
	closed    bool
	mutex     sync.Mutex
}

func newMockConn(readData []byte) *mockConn {
	return &mockConn{
		Buffer:   bytes.NewBuffer(nil),
		readData: readData,
	}
}

func (m *mockConn) Read(b []byte) (int, error) {
	if len(m.readData) == 0 {
		return 0, net.ErrClosed
	}
	n := copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
}
func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestServer_readAuthRequest(t *testing.T) {
	server := &Server{}

	t.Run("valid auth request", func(t *testing.T) {
		data := []byte{
			0x05,       // version
			0x02,       // number of methods
			0x00, 0x02, // methods: no auth, username/password
		}
		conn := newMockConn(data)

		req, err := server.readAuthRequest(conn)
		require.NoError(t, err)
		assert.Equal(t, byte(0x05), req.Version)
		assert.Equal(t, []byte{0x00, 0x02}, req.Methods)
	})

	t.Run("no methods provided", func(t *testing.T) {
		data := []byte{
			0x05, // version
			0x00, // number of methods = 0
		}
		conn := newMockConn(data)

		_, err := server.readAuthRequest(conn)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no authentication methods provided")
	})

	t.Run("connection error", func(t *testing.T) {
		conn := newMockConn([]byte{0x05}) // incomplete data
		_, err := server.readAuthRequest(conn)
		assert.Error(t, err)
	})
}

func TestServer_writeAuthResponse(t *testing.T) {
	server := &Server{}

	t.Run("successful write", func(t *testing.T) {
		conn := newMockConn(nil)
		resp := &AuthResponse{
			Version: 0x05,
			Method:  0x00,
		}

		err := server.writeAuthResponse(conn, resp)
		assert.NoError(t, err)
		assert.Equal(t, []byte{0x05, 0x00}, conn.writeData)
	})
}

func TestServer_readConnectRequest(t *testing.T) {
	server := &Server{}

	t.Run("IPv4 connect request", func(t *testing.T) {
		data := []byte{
			0x05,           // version
			0x01,           // command (CONNECT)
			0x00,           // reserved
			0x01,           // address type (IPv4)
			192, 168, 1, 1, // IPv4 address
			0x00, 0x50, // port 80
		}
		conn := newMockConn(data)

		req, err := server.readConnectRequest(conn)
		require.NoError(t, err)
		assert.Equal(t, byte(0x05), req.Version)
		assert.Equal(t, byte(0x01), req.Command)
		assert.Equal(t, byte(0x01), req.AddressType)
		assert.Equal(t, []byte{192, 168, 1, 1}, req.Address)
		assert.Equal(t, uint16(80), req.Port)
	})

	t.Run("IPv6 connect request", func(t *testing.T) {
		ipv6Addr := net.ParseIP("2001:db8::1").To16()
		data := make([]byte, 0)
		data = append(data, 0x05, 0x01, 0x00, 0x04) // version, command, reserved, IPv6 type
		data = append(data, ipv6Addr...)            // IPv6 address
		data = append(data, 0x01, 0xBB)             // port 443

		conn := newMockConn(data)

		req, err := server.readConnectRequest(conn)
		require.NoError(t, err)
		assert.Equal(t, byte(0x04), req.AddressType)
		assert.Equal(t, []byte(ipv6Addr), req.Address)
		assert.Equal(t, uint16(443), req.Port)
	})

	t.Run("domain connect request", func(t *testing.T) {
		domain := "example.com"
		data := []byte{
			0x05,              // version
			0x01,              // command
			0x00,              // reserved
			0x03,              // address type (domain)
			byte(len(domain)), // domain length
		}
		data = append(data, []byte(domain)...) // domain
		data = append(data, 0x00, 0x50)        // port 80

		conn := newMockConn(data)

		req, err := server.readConnectRequest(conn)
		require.NoError(t, err)
		assert.Equal(t, byte(0x03), req.AddressType)
		assert.Equal(t, []byte(domain), req.Address)
		assert.Equal(t, uint16(80), req.Port)
	})

	t.Run("zero domain length", func(t *testing.T) {
		data := []byte{
			0x05, // version
			0x01, // command
			0x00, // reserved
			0x03, // address type (domain)
			0x00, // domain length = 0
		}
		conn := newMockConn(data)

		_, err := server.readConnectRequest(conn)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "domain length cannot be zero")
	})

	t.Run("invalid address type", func(t *testing.T) {
		data := []byte{
			0x05, // version
			0x01, // command
			0x00, // reserved
			0xFF, // invalid address type
		}
		conn := newMockConn(data)

		_, err := server.readConnectRequest(conn)
		assert.Error(t, err)
	})
}

func TestServer_writeConnectResponse(t *testing.T) {
	server := &Server{}

	t.Run("successful response", func(t *testing.T) {
		conn := newMockConn(nil)
		resp := &ConnectResponse{
			Version:     0x05,
			Reply:       0x00,
			Reserved:    0x00,
			AddressType: 0x01,
			Address:     []byte{127, 0, 0, 1},
			Port:        8080,
		}

		err := server.writeConnectResponse(conn, resp)
		assert.NoError(t, err)

		expected := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90}
		assert.Equal(t, expected, conn.writeData)
	})
}

func TestServer_parseAddress(t *testing.T) {
	server := &Server{}

	t.Run("IPv4 address", func(t *testing.T) {
		req := &ConnectRequest{
			AddressType: AddressTypeIPv4,
			Address:     []byte{192, 168, 1, 1},
			Port:        80,
		}

		addr, err := server.parseAddress(req)
		require.NoError(t, err)
		assert.Equal(t, AddressTypeIPv4, addr.Type)
		assert.Equal(t, "192.168.1.1", addr.IP.String())
		assert.Equal(t, uint16(80), addr.Port)
	})

	t.Run("IPv6 address", func(t *testing.T) {
		ipv6 := net.ParseIP("2001:db8::1").To16()
		req := &ConnectRequest{
			AddressType: AddressTypeIPv6,
			Address:     ipv6,
			Port:        443,
		}

		addr, err := server.parseAddress(req)
		require.NoError(t, err)
		assert.Equal(t, AddressTypeIPv6, addr.Type)
		assert.Equal(t, "2001:db8::1", addr.IP.String())
		assert.Equal(t, uint16(443), addr.Port)
	})

	t.Run("domain address", func(t *testing.T) {
		req := &ConnectRequest{
			AddressType: AddressTypeDomain,
			Address:     []byte("example.com"),
			Port:        80,
		}

		addr, err := server.parseAddress(req)
		require.NoError(t, err)
		assert.Equal(t, AddressTypeDomain, addr.Type)
		assert.Equal(t, "example.com", addr.Host)
		assert.Equal(t, uint16(80), addr.Port)
	})

	t.Run("invalid IPv4 length", func(t *testing.T) {
		req := &ConnectRequest{
			AddressType: AddressTypeIPv4,
			Address:     []byte{192, 168, 1}, // only 3 bytes
			Port:        80,
		}

		_, err := server.parseAddress(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IPv4 address length")
	})

	t.Run("invalid IPv6 length", func(t *testing.T) {
		req := &ConnectRequest{
			AddressType: AddressTypeIPv6,
			Address:     []byte{1, 2, 3, 4}, // only 4 bytes
			Port:        80,
		}

		_, err := server.parseAddress(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IPv6 address length")
	})

	t.Run("invalid address type", func(t *testing.T) {
		req := &ConnectRequest{
			AddressType: 0xFF,
			Address:     []byte{192, 168, 1, 1},
			Port:        80,
		}

		_, err := server.parseAddress(req)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidAddressType, err)
	})
}

func TestServer_encodeAddress(t *testing.T) {
	server := &Server{}

	t.Run("IPv4 address", func(t *testing.T) {
		addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}

		addrType, address, port, err := server.encodeAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, AddressTypeIPv4, addrType)
		assert.Equal(t, []byte(net.ParseIP("192.168.1.1").To4()), address)
		assert.Equal(t, uint16(80), port)
	})

	t.Run("IPv6 address", func(t *testing.T) {
		addr := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}

		addrType, address, port, err := server.encodeAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, AddressTypeIPv6, addrType)
		assert.Equal(t, []byte(net.ParseIP("2001:db8::1").To16()), address)
		assert.Equal(t, uint16(443), port)
	})

	t.Run("domain address", func(t *testing.T) {
		// Create a mock address that will be treated as domain
		addr := &mockAddr{addr: "example.com:80"}

		addrType, address, port, err := server.encodeAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, AddressTypeDomain, addrType)
		assert.Equal(t, []byte("example.com"), address)
		assert.Equal(t, uint16(80), port)
	})

	t.Run("invalid port", func(t *testing.T) {
		addr := &mockAddr{addr: "example.com:invalid"}

		_, _, _, err := server.encodeAddress(addr)
		assert.Error(t, err)
	})
}

type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return m.addr }
