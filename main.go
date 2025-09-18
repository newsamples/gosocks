package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/newsamples/gosocks/internal/config"
	"github.com/newsamples/gosocks/internal/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func runServer(cmd *cobra.Command, _ []string) error {
	configFile, _ := cmd.Flags().GetString("config")

	// Load configuration (config file + environment variables)
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}

	// Only allow minimal command line overrides for operational purposes
	if cmd.Flags().Changed("log-level") {
		cfg.Log.Level, _ = cmd.Flags().GetString("log-level")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.Log.Level)
	if err != nil {
		return err
	}
	logger.SetLevel(level)

	serverConfig := &server.Config{
		BindAddress:  cfg.Server.BindAddress,
		EnableAuth:   cfg.Auth.Enable,
		Credentials:  cfg.GetCredentials(),
		EnableIPv6GW: cfg.Server.EnableIPv6GW,
		Logger:       logger,
	}

	srv, err := server.New(serverConfig)
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

	rootCmd.Flags().StringP("config", "c", "", "Path to configuration file (YAML format)")
	rootCmd.Flags().StringP("log-level", "l", "", "Override log level (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
