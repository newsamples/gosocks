package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/newsamples/gosocks/internal/routing"
	"github.com/sirupsen/logrus"
)

type Config struct {
	BindAddress    string
	AuthMethods    []byte
	Authenticator  Authenticator
	Logger         *logrus.Logger
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IPv6Gateway    bool
	Routes         []routing.Route
}

type Server struct {
	config   *Config
	listener net.Listener
	logger   *logrus.Logger
	router   *routing.Router
}

type Authenticator interface {
	Authenticate(conn net.Conn, method byte) error
	GetMethods() []byte
}

func NewServer(config *Config) (*Server, error) {
	if config.Logger == nil {
		config.Logger = logrus.New()
	}

	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 30 * time.Second
	}

	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}

	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}

	if len(config.AuthMethods) == 0 {
		config.AuthMethods = []byte{AuthMethodNoAuth}
	}

	server := &Server{
		config: config,
		logger: config.Logger,
	}

	// Initialize router if routes are configured
	if len(config.Routes) > 0 {
		router, err := routing.NewRouter(config.Routes)
		if err != nil {
			return nil, fmt.Errorf("failed to create router: %w", err)
		}
		server.router = router
	}

	return server, nil
}

func (s *Server) Listen(ctx context.Context) error {
	listener, err := s.createListener()
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.BindAddress, err)
	}

	s.listener = listener
	s.logger.Infof("SOCKS5 server listening on %s (dual-stack: %v)", s.config.BindAddress, s.isDualStackAddress())

	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Errorf("failed to accept connection: %v", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := s.setTimeouts(conn); err != nil {
		s.logger.Errorf("failed to set timeouts: %v", err)
		return
	}

	if err := s.handleAuth(conn); err != nil {
		s.logger.Errorf("authentication failed: %v", err)
		return
	}

	if err := s.handleRequest(conn); err != nil {
		s.logger.Errorf("request handling failed: %v", err)
		return
	}
}

func (s *Server) setTimeouts(conn net.Conn) error {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout)); err != nil {
			return err
		}
		if err := tcpConn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleAuth(conn net.Conn) error {
	authReq, err := s.readAuthRequest(conn)
	if err != nil {
		return err
	}

	if authReq.Version != Socks5Version {
		return ErrInvalidVersion
	}

	selectedMethod := s.selectAuthMethod(authReq.Methods)

	authResp := &AuthResponse{
		Version: Socks5Version,
		Method:  selectedMethod,
	}

	if err := s.writeAuthResponse(conn, authResp); err != nil {
		return err
	}

	if selectedMethod == AuthMethodNoAcceptable {
		return ErrNoAcceptableAuth
	}

	if selectedMethod != AuthMethodNoAuth && s.config.Authenticator != nil {
		return s.config.Authenticator.Authenticate(conn, selectedMethod)
	}

	return nil
}

func (s *Server) selectAuthMethod(clientMethods []byte) byte {
	for _, serverMethod := range s.config.AuthMethods {
		for _, clientMethod := range clientMethods {
			if serverMethod == clientMethod {
				return serverMethod
			}
		}
	}
	return AuthMethodNoAcceptable
}

func (s *Server) proxy(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	go func() {
		io.Copy(dst, src)
		dst.Close()
		src.Close()
	}()

	io.Copy(src, dst)
}

func (s *Server) createListener() (net.Listener, error) {
	// For dual-stack support, we need to handle IPv6 addresses that can accept IPv4 connections
	if s.isDualStackAddress() {
		// Try to create a dual-stack listener
		listener, err := net.Listen("tcp", s.config.BindAddress)
		if err != nil {
			return nil, err
		}

		// Check if this is a TCP listener that we can configure for dual-stack
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			// The Go net package automatically handles dual-stack for IPv6 addresses
			// when the system supports it
			s.logger.Debugf("Created dual-stack TCP listener on %s", s.config.BindAddress)
			return tcpListener, nil
		}
		return listener, nil
	}

	// Standard single-stack listener
	return net.Listen("tcp", s.config.BindAddress)
}

func (s *Server) isDualStackAddress() bool {
	host, _, err := net.SplitHostPort(s.config.BindAddress)
	if err != nil {
		// If we can't parse it, assume it's not dual-stack
		return false
	}

	// Check for IPv6 addresses that can accept IPv4 connections
	// This includes "::" (all interfaces) and specific IPv6 addresses
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// IPv6 addresses can potentially accept IPv4 connections via IPv4-mapped IPv6 addresses
	return ip.To4() == nil && (ip.IsUnspecified() || ip.To16() != nil)
}

func (s *Server) supportsDualStack() bool {
	return s.isDualStackAddress() || s.config.IPv6Gateway
}

func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
