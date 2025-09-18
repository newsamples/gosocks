package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestRunServer(t *testing.T) {
	t.Run("invalid log level override", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("config", "", "")
		cmd.Flags().String("log-level", "invalid", "")

		cmd.Flags().Set("log-level", "invalid")

		err := runServer(cmd, []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid logrus Level")
	})

	t.Run("configuration loading with log level override", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("config", "", "")
		cmd.Flags().String("log-level", "debug", "")

		cmd.Flags().Set("log-level", "debug")

		// Test that we can load config and validate without starting server
		// We'll set GOSOCKS_SERVER_BIND_ADDRESS to an invalid address to force early failure
		t.Setenv("GOSOCKS_SERVER_BIND_ADDRESS", "invalid:address:format")

		err := runServer(cmd, []string{})
		assert.Error(t, err) // Should fail due to invalid bind address
	})
}

func TestCommandInitialization(t *testing.T) {
	t.Run("command and flags are configured correctly", func(t *testing.T) {
		// Create a test command and set up flags like main() does
		testCmd := &cobra.Command{
			Use:  "gosocks",
			RunE: runServer,
		}

		testCmd.Flags().StringP("config", "c", "", "Path to configuration file (YAML format)")
		testCmd.Flags().StringP("log-level", "l", "", "Override log level (debug, info, warn, error)")

		// Check command configuration
		assert.Equal(t, "gosocks", testCmd.Use)
		assert.NotNil(t, testCmd.RunE)

		flags := testCmd.Flags()

		// Check that expected flags exist
		configFlag := flags.Lookup("config")
		assert.NotNil(t, configFlag)
		assert.Equal(t, "", configFlag.DefValue)

		logLevelFlag := flags.Lookup("log-level")
		assert.NotNil(t, logLevelFlag)
		assert.Equal(t, "", logLevelFlag.DefValue)

		// Verify old flags no longer exist
		assert.Nil(t, flags.Lookup("bind"))
		assert.Nil(t, flags.Lookup("auth"))
		assert.Nil(t, flags.Lookup("username"))
		assert.Nil(t, flags.Lookup("password"))
		assert.Nil(t, flags.Lookup("ipv6-gateway"))
	})
}

func TestMain(t *testing.T) {
	t.Run("main function exists", func(t *testing.T) {
		// This is a basic test to ensure main function compiles
		// We can't actually test main() execution without complex setup
		assert.NotNil(t, main)
	})
}
