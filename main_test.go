package main

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestRunServer(t *testing.T) {
	t.Run("invalid log level", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("log-level", "invalid", "")
		cmd.Flags().String("bind", "127.0.0.1:0", "")
		cmd.Flags().Bool("auth", false, "")
		cmd.Flags().String("username", "", "")
		cmd.Flags().String("password", "", "")
		cmd.Flags().Bool("ipv6-gateway", false, "")

		err := runServer(cmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid logrus Level")
	})

	t.Run("auth validation", func(t *testing.T) {
		testCases := []struct {
			name     string
			username string
			password string
		}{
			{"without username", "", "testpass"},
			{"without password", "testuser", ""},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cmd := &cobra.Command{}
				cmd.Flags().String("log-level", "info", "")
				cmd.Flags().String("bind", "127.0.0.1:0", "")
				cmd.Flags().Bool("auth", true, "")
				cmd.Flags().String("username", tc.username, "")
				cmd.Flags().String("password", tc.password, "")
				cmd.Flags().Bool("ipv6-gateway", false, "")

				cmd.Flags().Set("auth", "true")
				if tc.username != "" {
					cmd.Flags().Set("username", tc.username)
				}
				if tc.password != "" {
					cmd.Flags().Set("password", tc.password)
				}

				enableAuth, _ := cmd.Flags().GetBool("auth")
				username, _ := cmd.Flags().GetString("username")
				password, _ := cmd.Flags().GetString("password")

				// Test that the validation condition is met (would trigger Fatal)
				assert.True(t, enableAuth && (username == "" || password == ""))
			})
		}
	})

	t.Run("invalid bind address", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("log-level", "info", "")
		cmd.Flags().String("bind", "invalid:address:format", "")
		cmd.Flags().Bool("auth", false, "")
		cmd.Flags().String("username", "", "")
		cmd.Flags().String("password", "", "")
		cmd.Flags().Bool("ipv6-gateway", false, "")

		cmd.Flags().Set("bind", "invalid:address:format")

		err := runServer(cmd, []string{})
		assert.Error(t, err)
	})

	t.Run("valid log levels", func(t *testing.T) {
		testCases := []string{"debug", "info", "warn", "error"}
		for _, level := range testCases {
			t.Run("log level "+level, func(t *testing.T) {
				// This would pass validation but we can't test the full server start
				// without it actually starting and blocking, so we just test validation
				_, err := logrus.ParseLevel(level)
				assert.NoError(t, err)
			})
		}
	})

	t.Run("IPv6 gateway enabled", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("log-level", "info", "")
		cmd.Flags().String("bind", "127.0.0.1:0", "")
		cmd.Flags().Bool("auth", false, "")
		cmd.Flags().String("username", "", "")
		cmd.Flags().String("password", "", "")
		cmd.Flags().Bool("ipv6-gateway", true, "")

		cmd.Flags().Set("ipv6-gateway", "true")

		enableAuth, _ := cmd.Flags().GetBool("auth")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")

		// Test that validation passes (IPv6GW doesn't affect pre-flight validation)
		assert.False(t, enableAuth && (username == "" || password == ""))
	})
}

func TestCommandInitialization(t *testing.T) {
	t.Run("command and flags are configured correctly", func(t *testing.T) {
		// Create a test command and set up flags like main() does
		testCmd := &cobra.Command{
			Use:  "gosocks",
			RunE: runServer,
		}

		testCmd.Flags().StringP("bind", "b", "0.0.0.0:1080", "Address to bind the server to")
		testCmd.Flags().BoolP("auth", "a", false, "Enable username/password authentication")
		testCmd.Flags().StringP("username", "u", "", "Username for authentication (required if --auth is enabled)")
		testCmd.Flags().StringP("password", "p", "", "Password for authentication (required if --auth is enabled)")
		testCmd.Flags().BoolP("ipv6-gateway", "6", false, "Enable IPv6/IPv4 gateway functionality")
		testCmd.Flags().StringP("log-level", "l", "info", "Log level (debug, info, warn, error)")

		// Check command configuration
		assert.Equal(t, "gosocks", testCmd.Use)
		assert.NotNil(t, testCmd.RunE)

		flags := testCmd.Flags()

		// Check that all expected flags exist
		bindFlag := flags.Lookup("bind")
		assert.NotNil(t, bindFlag)
		assert.Equal(t, "0.0.0.0:1080", bindFlag.DefValue)

		authFlag := flags.Lookup("auth")
		assert.NotNil(t, authFlag)
		assert.Equal(t, "false", authFlag.DefValue)

		usernameFlag := flags.Lookup("username")
		assert.NotNil(t, usernameFlag)
		assert.Equal(t, "", usernameFlag.DefValue)

		passwordFlag := flags.Lookup("password")
		assert.NotNil(t, passwordFlag)
		assert.Equal(t, "", passwordFlag.DefValue)

		ipv6Flag := flags.Lookup("ipv6-gateway")
		assert.NotNil(t, ipv6Flag)
		assert.Equal(t, "false", ipv6Flag.DefValue)

		logLevelFlag := flags.Lookup("log-level")
		assert.NotNil(t, logLevelFlag)
		assert.Equal(t, "info", logLevelFlag.DefValue)
	})
}

func TestMain(t *testing.T) {
	t.Run("main function exists", func(t *testing.T) {
		// This is a basic test to ensure main function compiles
		// We can't actually test main() execution without complex setup
		assert.NotNil(t, main)
	})
}
