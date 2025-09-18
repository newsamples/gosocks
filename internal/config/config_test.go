package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Run("load default configuration without file", func(t *testing.T) {
		cfg, err := Load("")
		require.NoError(t, err)

		assert.Equal(t, "0.0.0.0:1080", cfg.Server.BindAddress)
		assert.Equal(t, 30*time.Second, cfg.Server.ConnectTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
		assert.False(t, cfg.Server.EnableIPv6GW)
		assert.False(t, cfg.Auth.Enable)
		assert.Empty(t, cfg.Auth.Users)
		assert.Equal(t, "info", cfg.Log.Level)
	})

	t.Run("load configuration from YAML file", func(t *testing.T) {
		yamlContent := `
server:
  bind_address: "127.0.0.1:8080"
  connect_timeout: 60s
  read_timeout: 45s
  write_timeout: 45s
  enable_ipv6_gateway: true

auth:
  enable: true
  users:
    - username: "testuser"
      password: "testpass"

log:
  level: "debug"
`
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "config.yaml")
		err := os.WriteFile(configFile, []byte(yamlContent), 0644)
		require.NoError(t, err)

		cfg, err := Load(configFile)
		require.NoError(t, err)

		assert.Equal(t, "127.0.0.1:8080", cfg.Server.BindAddress)
		assert.Equal(t, 60*time.Second, cfg.Server.ConnectTimeout)
		assert.Equal(t, 45*time.Second, cfg.Server.ReadTimeout)
		assert.Equal(t, 45*time.Second, cfg.Server.WriteTimeout)
		assert.True(t, cfg.Server.EnableIPv6GW)
		assert.True(t, cfg.Auth.Enable)
		credentials := cfg.GetCredentials()
		assert.Equal(t, "testpass", credentials["testuser"])
		assert.Equal(t, "debug", cfg.Log.Level)
	})

	t.Run("load configuration from environment variables", func(t *testing.T) {
		t.Setenv("GOSOCKS_SERVER_BIND_ADDRESS", "192.168.1.1:9090")
		t.Setenv("GOSOCKS_SERVER_CONNECT_TIMEOUT", "2m")
		t.Setenv("GOSOCKS_SERVER_READ_TIMEOUT", "1m30s")
		t.Setenv("GOSOCKS_SERVER_WRITE_TIMEOUT", "1m30s")
		t.Setenv("GOSOCKS_SERVER_ENABLE_IPV6_GATEWAY", "true")
		t.Setenv("GOSOCKS_AUTH_ENABLE", "false")
		t.Setenv("GOSOCKS_LOG_LEVEL", "warn")

		cfg, err := Load("")
		require.NoError(t, err)

		assert.Equal(t, "192.168.1.1:9090", cfg.Server.BindAddress)
		assert.Equal(t, 2*time.Minute, cfg.Server.ConnectTimeout)
		assert.Equal(t, 90*time.Second, cfg.Server.ReadTimeout)
		assert.Equal(t, 90*time.Second, cfg.Server.WriteTimeout)
		assert.True(t, cfg.Server.EnableIPv6GW)
		assert.False(t, cfg.Auth.Enable)
		assert.Empty(t, cfg.Auth.Users)
		assert.Equal(t, "warn", cfg.Log.Level)
	})

	t.Run("load nonexistent file returns default config", func(t *testing.T) {
		cfg, err := Load("/nonexistent/config.yaml")
		require.NoError(t, err)

		// Should return default configuration when file doesn't exist
		assert.Equal(t, "0.0.0.0:1080", cfg.Server.BindAddress)
		assert.Equal(t, "info", cfg.Log.Level)
	})

	t.Run("load invalid YAML file", func(t *testing.T) {
		invalidYaml := `
server:
  bind_address: "127.0.0.1:8080"
  invalid_yaml: [
`
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "invalid.yaml")
		err := os.WriteFile(configFile, []byte(invalidYaml), 0644)
		require.NoError(t, err)

		_, err = Load(configFile)
		assert.Error(t, err)
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Run("valid configuration without auth", func(t *testing.T) {
		cfg := &Config{
			Server: ServerConfig{
				BindAddress: "127.0.0.1:1080",
			},
			Auth: AuthConfig{
				Enable: false,
			},
			Log: LogConfig{
				Level: "info",
			},
		}

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid configuration with users array", func(t *testing.T) {
		cfg := &Config{
			Auth: AuthConfig{
				Enable: true,
				Users: []UserCredential{
					{Username: "alice", Password: "secret1"},
					{Username: "bob", Password: "secret2"},
				},
			},
		}

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("auth enabled without any credentials", func(t *testing.T) {
		cfg := &Config{
			Auth: AuthConfig{
				Enable: true,
			},
		}

		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication is enabled but no valid credentials configured")
	})

	t.Run("auth enabled with incomplete users", func(t *testing.T) {
		cfg := &Config{
			Auth: AuthConfig{
				Enable: true,
				Users: []UserCredential{
					{Username: "alice", Password: ""},
					{Username: "", Password: "secret2"},
				},
			},
		}

		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "all users must have both username and password")
	})

	t.Run("auth enabled with duplicate usernames", func(t *testing.T) {
		cfg := &Config{
			Auth: AuthConfig{
				Enable: true,
				Users: []UserCredential{
					{Username: "alice", Password: "secret1"},
					{Username: "alice", Password: "secret2"},
				},
			},
		}

		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate username found: alice")
	})
}

func TestConfig_GetCredentials(t *testing.T) {

	t.Run("users array", func(t *testing.T) {
		cfg := &Config{
			Auth: AuthConfig{
				Users: []UserCredential{
					{Username: "alice", Password: "secret1"},
					{Username: "bob", Password: "secret2"},
				},
			},
		}

		credentials := cfg.GetCredentials()
		expected := map[string]string{
			"alice": "secret1",
			"bob":   "secret2",
		}
		assert.Equal(t, expected, credentials)
	})

	t.Run("multiple users", func(t *testing.T) {
		cfg := &Config{
			Auth: AuthConfig{
				Users: []UserCredential{
					{Username: "alice", Password: "secret1"},
					{Username: "bob", Password: "secret2"},
					{Username: "user1", Password: "pass1"},
					{Username: "user2", Password: "pass2"},
				},
			},
		}

		credentials := cfg.GetCredentials()
		expected := map[string]string{
			"alice": "secret1",
			"bob":   "secret2",
			"user1": "pass1",
			"user2": "pass2",
		}
		assert.Equal(t, expected, credentials)
	})

	t.Run("filter empty credentials", func(t *testing.T) {
		cfg := &Config{
			Auth: AuthConfig{
				Users: []UserCredential{
					{Username: "user1", Password: "pass1"},
					{Username: "alice", Password: "secret1"},
					{Username: "", Password: "secret2"},
					{Username: "bob", Password: ""},
				},
			},
		}

		credentials := cfg.GetCredentials()
		expected := map[string]string{
			"user1": "pass1",
			"alice": "secret1",
		}
		assert.Equal(t, expected, credentials)
	})

}

func TestServerConfig(t *testing.T) {
	t.Run("default server config values", func(t *testing.T) {
		cfg, err := Load("")
		require.NoError(t, err)

		assert.Equal(t, "0.0.0.0:1080", cfg.Server.BindAddress)
		assert.Equal(t, 30*time.Second, cfg.Server.ConnectTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
		assert.False(t, cfg.Server.EnableIPv6GW)
	})
}

func TestAuthConfig(t *testing.T) {
	t.Run("default auth config values", func(t *testing.T) {
		cfg, err := Load("")
		require.NoError(t, err)

		assert.False(t, cfg.Auth.Enable)
		assert.Empty(t, cfg.Auth.Users)
	})
}

func TestLogConfig(t *testing.T) {
	t.Run("default log config values", func(t *testing.T) {
		cfg, err := Load("")
		require.NoError(t, err)

		assert.Equal(t, "info", cfg.Log.Level)
	})
}
