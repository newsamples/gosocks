package server

import (
	"context"
	"time"

	"github.com/newsamples/gosocks/internal/auth"
	"github.com/newsamples/gosocks/internal/socks5"
	"github.com/sirupsen/logrus"
)

type Config struct {
	BindAddress  string
	EnableAuth   bool
	Username     string
	Password     string
	EnableIPv6GW bool
	Logger       *logrus.Logger
}

type Server struct {
	socks5Server *socks5.Server
}

func New(config *Config) (*Server, error) {
	socks5Config := &socks5.Config{
		BindAddress:    config.BindAddress,
		Logger:         config.Logger,
		ConnectTimeout: 30 * time.Second,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IPv6Gateway:    config.EnableIPv6GW,
	}

	if config.EnableAuth {
		credentials := map[string]string{
			config.Username: config.Password,
		}
		authenticator := auth.NewUserPassAuthenticator(credentials)
		socks5Config.Authenticator = authenticator
		socks5Config.AuthMethods = []byte{socks5.AuthMethodUserPass}
	} else {
		socks5Config.AuthMethods = []byte{socks5.AuthMethodNoAuth}
	}

	socks5Server, err := socks5.NewServer(socks5Config)
	if err != nil {
		return nil, err
	}

	return &Server{
		socks5Server: socks5Server,
	}, nil
}

func (s *Server) Listen(ctx context.Context) error {
	return s.socks5Server.Listen(ctx)
}

func (s *Server) Close() error {
	return s.socks5Server.Close()
}
