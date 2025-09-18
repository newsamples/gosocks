package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/newsamples/gosocks/internal/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func runServer(cmd *cobra.Command, _ []string) error {
	bindAddress, _ := cmd.Flags().GetString("bind")
	enableAuth, _ := cmd.Flags().GetBool("auth")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	enableIPv6GW, _ := cmd.Flags().GetBool("ipv6-gateway")
	logLevel, _ := cmd.Flags().GetString("log-level")

	logger := logrus.New()
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return err
	}
	logger.SetLevel(level)

	if enableAuth && (username == "" || password == "") {
		logger.Fatal("Username and password are required when authentication is enabled")
	}

	config := &server.Config{
		BindAddress:  bindAddress,
		EnableAuth:   enableAuth,
		Username:     username,
		Password:     password,
		EnableIPv6GW: enableIPv6GW,
		Logger:       logger,
	}

	srv, err := server.New(config)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()
	}()

	logger.Info("Starting SOCKS5 server...")
	return srv.Listen(ctx)
}

func main() {
	rootCmd := &cobra.Command{
		Use:  "gosocks",
		RunE: runServer,
	}

	rootCmd.Flags().StringP("bind", "b", "0.0.0.0:1080", "Address to bind the server to")
	rootCmd.Flags().BoolP("auth", "a", false, "Enable username/password authentication")
	rootCmd.Flags().StringP("username", "u", "", "Username for authentication (required if --auth is enabled)")
	rootCmd.Flags().StringP("password", "p", "", "Password for authentication (required if --auth is enabled)")
	rootCmd.Flags().BoolP("ipv6-gateway", "6", false, "Enable IPv6/IPv4 gateway functionality")
	rootCmd.Flags().StringP("log-level", "l", "info", "Log level (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
