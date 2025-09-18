package auth

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockConn struct {
	*bytes.Buffer
	readData  []byte
	writeData []byte
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

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestNewUserPassAuthenticator(t *testing.T) {
	credentials := map[string]string{
		"user1": "pass1",
		"user2": "pass2",
	}

	auth := NewUserPassAuthenticator(credentials)
	assert.NotNil(t, auth)
	assert.Equal(t, credentials, auth.credentials)
}

func TestUserPassAuthenticator_GetMethods(t *testing.T) {
	auth := NewUserPassAuthenticator(nil)
	methods := auth.GetMethods()
	assert.Equal(t, []byte{0x02}, methods)
}

func TestUserPassAuthenticator_Authenticate(t *testing.T) {
	credentials := map[string]string{
		"testuser": "testpass",
	}
	auth := NewUserPassAuthenticator(credentials)

	t.Run("successful authentication", func(t *testing.T) {
		readData := []byte{
			0x01,                                   // version
			0x08,                                   // username length
			't', 'e', 's', 't', 'u', 's', 'e', 'r', // username
			0x08,                                   // password length
			't', 'e', 's', 't', 'p', 'a', 's', 's', // password
		}

		conn := newMockConn(readData)
		err := auth.Authenticate(conn, 0x02)
		assert.NoError(t, err)

		expected := []byte{0x01, 0x00} // version, success status
		assert.Equal(t, expected, conn.writeData)
	})

	t.Run("failed authentication - wrong password", func(t *testing.T) {
		readData := []byte{
			0x01,                                   // version
			0x08,                                   // username length
			't', 'e', 's', 't', 'u', 's', 'e', 'r', // username
			0x09,                                        // password length
			'w', 'r', 'o', 'n', 'g', 'p', 'a', 's', 's', // wrong password
		}

		conn := newMockConn(readData)
		err := auth.Authenticate(conn, 0x02)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")

		expected := []byte{0x01, 0x01} // version, failure status
		assert.Equal(t, expected, conn.writeData)
	})

	t.Run("failed authentication - user not found", func(t *testing.T) {
		readData := []byte{
			0x01,                              // version
			0x07,                              // username length
			'u', 'n', 'k', 'n', 'o', 'w', 'n', // unknown user
			0x08,                                   // password length
			't', 'e', 's', 't', 'p', 'a', 's', 's', // password
		}

		conn := newMockConn(readData)
		err := auth.Authenticate(conn, 0x02)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
	})

	t.Run("invalid method", func(t *testing.T) {
		conn := newMockConn(nil)
		err := auth.Authenticate(conn, 0x01)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported authentication method")
	})

	t.Run("invalid version", func(t *testing.T) {
		readData := []byte{
			0x02, // invalid version
			0x08,
			't', 'e', 's', 't', 'u', 's', 'e', 'r',
			0x08,
			't', 'e', 's', 't', 'p', 'a', 's', 's',
		}

		conn := newMockConn(readData)
		err := auth.Authenticate(conn, 0x02)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid username/password version")
	})
}

func TestUserPassAuthenticator_readUserPassRequest(t *testing.T) {
	auth := NewUserPassAuthenticator(nil)

	t.Run("valid request", func(t *testing.T) {
		readData := []byte{
			0x01,               // version
			0x04,               // username length
			'u', 's', 'e', 'r', // username
			0x04,               // password length
			'p', 'a', 's', 's', // password
		}

		conn := newMockConn(readData)
		req, err := auth.readUserPassRequest(conn)
		require.NoError(t, err)

		assert.Equal(t, byte(0x01), req.Version)
		assert.Equal(t, "user", req.Username)
		assert.Equal(t, "pass", req.Password)
	})

	t.Run("empty password", func(t *testing.T) {
		readData := []byte{
			0x01,               // version
			0x04,               // username length
			'u', 's', 'e', 'r', // username
			0x00, // password length (empty)
		}

		conn := newMockConn(readData)
		req, err := auth.readUserPassRequest(conn)
		require.NoError(t, err)

		assert.Equal(t, "user", req.Username)
		assert.Equal(t, "", req.Password)
	})

	t.Run("zero username length", func(t *testing.T) {
		readData := []byte{
			0x01, // version
			0x00, // username length (zero)
		}

		conn := newMockConn(readData)
		_, err := auth.readUserPassRequest(conn)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username length cannot be zero")
	})
}

func TestUserPassAuthenticator_writeUserPassResponse(t *testing.T) {
	auth := NewUserPassAuthenticator(nil)

	t.Run("success response", func(t *testing.T) {
		conn := newMockConn(nil)
		resp := &UserPassResponse{
			Version: UserPassVersion,
			Status:  AuthStatusSuccess,
		}

		err := auth.writeUserPassResponse(conn, resp)
		assert.NoError(t, err)

		expected := []byte{0x01, 0x00}
		assert.Equal(t, expected, conn.writeData)
	})

	t.Run("failure response", func(t *testing.T) {
		conn := newMockConn(nil)
		resp := &UserPassResponse{
			Version: UserPassVersion,
			Status:  AuthStatusFailure,
		}

		err := auth.writeUserPassResponse(conn, resp)
		assert.NoError(t, err)

		expected := []byte{0x01, 0x01}
		assert.Equal(t, expected, conn.writeData)
	})
}
