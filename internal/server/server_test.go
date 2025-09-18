package server

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("valid config without auth", func(t *testing.T) {
		config := &Config{
			BindAddress:  "127.0.0.1:0",
			EnableAuth:   false,
			EnableIPv6GW: false,
			Logger:       logrus.New(),
		}

		server, err := New(config)
		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.NotNil(t, server.socks5Server)
	})

	t.Run("valid config with single user auth", func(t *testing.T) {
		config := &Config{
			BindAddress: "127.0.0.1:0",
			EnableAuth:  true,
			Credentials: map[string]string{
				"testuser": "testpass",
			},
			EnableIPv6GW: false,
			Logger:       logrus.New(),
		}

		server, err := New(config)
		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.NotNil(t, server.socks5Server)
	})

	t.Run("valid config with multiple users auth", func(t *testing.T) {
		config := &Config{
			BindAddress: "127.0.0.1:0",
			EnableAuth:  true,
			Credentials: map[string]string{
				"user1": "pass1",
				"user2": "pass2",
				"admin": "adminpass",
			},
			EnableIPv6GW: false,
			Logger:       logrus.New(),
		}

		server, err := New(config)
		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.NotNil(t, server.socks5Server)
	})

	t.Run("valid config with IPv6 gateway", func(t *testing.T) {
		config := &Config{
			BindAddress:  "127.0.0.1:0",
			EnableAuth:   false,
			EnableIPv6GW: true,
			Logger:       logrus.New(),
		}

		server, err := New(config)
		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.NotNil(t, server.socks5Server)
	})

	t.Run("invalid bind address during listen", func(t *testing.T) {
		config := &Config{
			BindAddress:  "invalid:address:format",
			EnableAuth:   false,
			EnableIPv6GW: false,
			Logger:       logrus.New(),
		}

		server, err := New(config)
		require.NoError(t, err) // NewServer doesn't validate bind address

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Listen should fail with invalid address
		err = server.Listen(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to listen")
	})
}

func TestServer_Listen(t *testing.T) {
	t.Run("start and stop server", func(t *testing.T) {
		config := &Config{
			BindAddress:  "127.0.0.1:0",
			EnableAuth:   false,
			EnableIPv6GW: false,
			Logger:       logrus.New(),
		}

		server, err := New(config)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Start server in goroutine since Listen blocks
		done := make(chan error, 1)
		go func() {
			done <- server.Listen(ctx)
		}()

		// Wait for context timeout or error
		select {
		case err := <-done:
			// Server should stop when context is cancelled
			if err != nil && err != context.Canceled {
				t.Errorf("Expected context.Canceled or nil, got: %v", err)
			}
		case <-time.After(200 * time.Millisecond):
			t.Error("Server did not stop within expected time")
		}
	})
}

func TestServer_Close(t *testing.T) {
	t.Run("close server", func(t *testing.T) {
		config := &Config{
			BindAddress:  "127.0.0.1:0",
			EnableAuth:   false,
			EnableIPv6GW: false,
			Logger:       logrus.New(),
		}

		server, err := New(config)
		require.NoError(t, err)

		// Close should not error even if server wasn't started
		err = server.Close()
		assert.NoError(t, err)
	})
}
