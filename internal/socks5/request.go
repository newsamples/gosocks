package socks5

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/newsamples/gosocks/internal/routing"
)

func (s *Server) handleRequest(conn net.Conn) error {
	req, err := s.readConnectRequest(conn)
	if err != nil {
		return err
	}

	if req.Version != Socks5Version {
		s.sendErrorResponse(conn, ReplyGeneralFailure)
		return ErrInvalidVersion
	}

	switch req.Command {
	case CommandConnect:
		return s.handleConnect(conn, req)
	case CommandBind:
		return s.handleBind(conn, req)
	case CommandUDPAssociate:
		return s.handleUDPAssociate(conn, req)
	default:
		s.sendErrorResponse(conn, ReplyCommandNotSupported)
		return ErrInvalidCommand
	}
}

func (s *Server) handleConnect(conn net.Conn, req *ConnectRequest) error {
	addr, err := s.parseAddress(req)
	if err != nil {
		s.sendErrorResponse(conn, ReplyAddressTypeNotSupported)
		return err
	}

	targetAddr := s.resolveAddress(addr)

	targetConn, err := s.dialTarget(targetAddr)
	if err != nil {
		s.sendErrorResponse(conn, s.getErrorReply(err))
		return err
	}

	localAddr := targetConn.LocalAddr()
	addressType, address, port, err := s.encodeAddress(localAddr)
	if err != nil {
		targetConn.Close()
		s.sendErrorResponse(conn, ReplyGeneralFailure)
		return err
	}

	resp := &ConnectResponse{
		Version:     Socks5Version,
		Reply:       ReplySucceeded,
		Reserved:    0,
		AddressType: addressType,
		Address:     address,
		Port:        port,
	}

	if err := s.writeConnectResponse(conn, resp); err != nil {
		targetConn.Close()
		return err
	}

	s.proxy(targetConn, conn)
	return nil
}

func (s *Server) handleBind(conn net.Conn, req *ConnectRequest) error {
	// Parse the target address that we expect to connect to us
	targetAddr, err := s.parseAddress(req)
	if err != nil {
		s.sendErrorResponse(conn, ReplyAddressTypeNotSupported)
		return err
	}

	// Create a listener on any available port
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		s.sendErrorResponse(conn, ReplyGeneralFailure)
		return fmt.Errorf("failed to create bind listener: %w", err)
	}
	defer listener.Close()

	// Get the bound address
	boundAddr := listener.Addr()
	addressType, address, port, err := s.encodeAddress(boundAddr)
	if err != nil {
		s.sendErrorResponse(conn, ReplyGeneralFailure)
		return err
	}

	// Send first response with bound address
	resp := &ConnectResponse{
		Version:     Socks5Version,
		Reply:       ReplySucceeded,
		Reserved:    0,
		AddressType: addressType,
		Address:     address,
		Port:        port,
	}

	if err := s.writeConnectResponse(conn, resp); err != nil {
		return err
	}

	s.logger.Infof("BIND listening on %s, expecting connection from %s", boundAddr, targetAddr)

	// Set deadline for accept operation to prevent indefinite blocking in tests
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		tcpListener.SetDeadline(time.Now().Add(s.config.ConnectTimeout))
	}

	// Wait for incoming connection
	incomingConn, err := listener.Accept()
	if err != nil {
		s.sendErrorResponse(conn, ReplyConnectionRefused)
		return fmt.Errorf("failed to accept bind connection: %w", err)
	}
	defer incomingConn.Close()

	// Validate that the incoming connection is from the expected address
	incomingAddr := incomingConn.RemoteAddr()
	if !s.validateBindConnection(targetAddr, incomingAddr) {
		s.sendErrorResponse(conn, ReplyConnectionNotAllowed)
		return fmt.Errorf("bind connection from unexpected address: %s (expected: %s)", incomingAddr, targetAddr)
	}

	// Get the actual remote address of the incoming connection
	incomingAddrType, incomingAddress, incomingPort, err := s.encodeAddress(incomingAddr)
	if err != nil {
		s.sendErrorResponse(conn, ReplyGeneralFailure)
		return err
	}

	// Send second response with the incoming connection address
	secondResp := &ConnectResponse{
		Version:     Socks5Version,
		Reply:       ReplySucceeded,
		Reserved:    0,
		AddressType: incomingAddrType,
		Address:     incomingAddress,
		Port:        incomingPort,
	}

	if err := s.writeConnectResponse(conn, secondResp); err != nil {
		return err
	}

	s.logger.Infof("BIND connection established from %s", incomingAddr)

	// Start proxying data between the client and the incoming connection
	s.proxy(incomingConn, conn)
	return nil
}

func (s *Server) handleUDPAssociate(conn net.Conn, req *ConnectRequest) error {
	// Parse the client's expected address (usually 0.0.0.0:0 for any)
	clientAddr, err := s.parseAddress(req)
	if err != nil {
		s.sendErrorResponse(conn, ReplyAddressTypeNotSupported)
		return err
	}

	// Create a UDP listener on any available port
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		s.sendErrorResponse(conn, ReplyGeneralFailure)
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.sendErrorResponse(conn, ReplyGeneralFailure)
		return fmt.Errorf("failed to create UDP listener: %w", err)
	}
	defer udpConn.Close()

	// Get the bound UDP address
	boundAddr := udpConn.LocalAddr()
	addressType, address, port, err := s.encodeAddress(boundAddr)
	if err != nil {
		s.sendErrorResponse(conn, ReplyGeneralFailure)
		return err
	}

	// Send success response with UDP relay address
	resp := &ConnectResponse{
		Version:     Socks5Version,
		Reply:       ReplySucceeded,
		Reserved:    0,
		AddressType: addressType,
		Address:     address,
		Port:        port,
	}

	if err := s.writeConnectResponse(conn, resp); err != nil {
		return err
	}

	s.logger.Infof("UDP ASSOCIATE relay listening on %s for client %s", boundAddr, clientAddr)

	// Start UDP relay in a goroutine
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- s.runUDPRelay(udpConn, conn.RemoteAddr())
	}()

	// Monitor TCP connection for close
	tcpDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		tcpDone <- err
	}()

	// Wait for either TCP connection to close or UDP relay to fail
	select {
	case err := <-relayDone:
		s.logger.Infof("UDP relay stopped: %v", err)
		return err
	case err := <-tcpDone:
		s.logger.Infof("TCP control connection closed: %v", err)
		return err
	}
}

func (s *Server) resolveAddress(addr *Address) string {
	if s.config.IPv6Gateway && addr.Type == AddressTypeIPv4 {
		if addr.IP != nil {
			ipv6 := make(net.IP, 16)
			copy(ipv6[12:], addr.IP.To4())
			ipv6[10] = 0xff
			ipv6[11] = 0xff
			return net.JoinHostPort(ipv6.String(), fmt.Sprintf("%d", addr.Port))
		}
	}

	if addr.IP != nil {
		return net.JoinHostPort(addr.IP.String(), fmt.Sprintf("%d", addr.Port))
	}

	return net.JoinHostPort(addr.Host, fmt.Sprintf("%d", addr.Port))
}

func (s *Server) dialTarget(address string) (net.Conn, error) {
	// Check if we have routing configured
	if s.router != nil {
		if route, found := s.router.FindRoute(address); found {
			// Use upstream SOCKS5 server
			timeout := route.Timeout
			if timeout == 0 {
				timeout = s.config.ConnectTimeout
			}

			upstreamDialer := routing.NewUpstreamDialer(route.Upstream, timeout)
			return upstreamDialer.Dial("tcp", address)
		}
	}

	// Default direct connection
	dialer := &net.Dialer{
		Timeout: s.config.ConnectTimeout,
	}

	return dialer.Dial("tcp", address)
}

func (s *Server) sendErrorResponse(conn net.Conn, reply byte) {
	resp := &ConnectResponse{
		Version:     Socks5Version,
		Reply:       reply,
		Reserved:    0,
		AddressType: AddressTypeIPv4,
		Address:     []byte{0, 0, 0, 0},
		Port:        0,
	}

	s.writeConnectResponse(conn, resp)
}

func (s *Server) getErrorReply(err error) byte {
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return ReplyTTLExpired
		}
	}

	switch err.(type) {
	case *net.DNSError:
		return ReplyHostUnreachable
	case *net.AddrError:
		return ReplyAddressTypeNotSupported
	default:
		if opErr, ok := err.(*net.OpError); ok {
			switch opErr.Op {
			case "dial":
				return ReplyConnectionRefused
			case "read", "write":
				return ReplyNetworkUnreachable
			}
		}
	}

	return ReplyGeneralFailure
}

func (s *Server) validateBindConnection(expectedAddr *Address, incomingAddr net.Addr) bool {
	// Extract host from incoming address
	host, _, err := net.SplitHostPort(incomingAddr.String())
	if err != nil {
		return false
	}

	incomingIP := net.ParseIP(host)
	if incomingIP == nil {
		return false
	}

	// Check against expected address
	switch expectedAddr.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		if expectedAddr.IP != nil {
			return expectedAddr.IP.Equal(incomingIP)
		}
	case AddressTypeDomain:
		// For domain names, resolve and compare
		ips, err := net.LookupIP(expectedAddr.Host)
		if err != nil {
			return false
		}
		for _, ip := range ips {
			if ip.Equal(incomingIP) {
				return true
			}
		}
	}

	return false
}

func (s *Server) runUDPRelay(udpConn *net.UDPConn, clientAddr net.Addr) error {
	clientUDPAddr, ok := clientAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("invalid client address type")
	}

	// Convert TCP address to UDP for client communication
	clientUDP := &net.UDPAddr{
		IP:   clientUDPAddr.IP,
		Port: clientUDPAddr.Port,
	}

	// Cache for target connections
	targetCache := make(map[string]*net.UDPConn)
	defer func() {
		for _, conn := range targetCache {
			conn.Close()
		}
	}()

	buf := make([]byte, 65536) // Maximum UDP packet size

	for {
		n, fromAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("UDP read error: %w", err)
		}

		// Parse the SOCKS UDP header
		header, err := s.parseUDPHeader(buf[:n])
		if err != nil {
			s.logger.Warnf("Invalid UDP header from %s: %v", fromAddr, err)
			continue
		}

		// Determine target address
		var targetAddr string
		switch header.AddressType {
		case AddressTypeIPv4:
			targetAddr = net.JoinHostPort(net.IP(header.Address).String(), fmt.Sprintf("%d", header.Port))
		case AddressTypeIPv6:
			targetAddr = net.JoinHostPort(net.IP(header.Address).String(), fmt.Sprintf("%d", header.Port))
		case AddressTypeDomain:
			targetAddr = net.JoinHostPort(string(header.Address), fmt.Sprintf("%d", header.Port))
		default:
			s.logger.Warnf("Unsupported address type %d from %s", header.AddressType, fromAddr)
			continue
		}

		// Check if packet is from our client
		if fromAddr.String() == clientUDP.String() {
			// Forward to target
			err = s.forwardUDPToTarget(targetAddr, header.Data, targetCache, udpConn, fromAddr)
			if err != nil {
				s.logger.Warnf("Failed to forward UDP to target %s: %v", targetAddr, err)
			}
		} else {
			// This might be a response from a target, forward back to client
			err = s.forwardUDPToClient(udpConn, clientUDP, fromAddr, buf[:n])
			if err != nil {
				s.logger.Warnf("Failed to forward UDP to client: %v", err)
			}
		}
	}
}

func (s *Server) forwardUDPToTarget(targetAddr string, data []byte, cache map[string]*net.UDPConn, relayConn *net.UDPConn, clientAddr *net.UDPAddr) error {
	// Get or create connection to target
	targetConn, exists := cache[targetAddr]
	if !exists {
		udpTargetAddr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			return fmt.Errorf("failed to resolve target address %s: %w", targetAddr, err)
		}

		targetConn, err = net.DialUDP("udp", nil, udpTargetAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to target %s: %w", targetAddr, err)
		}

		cache[targetAddr] = targetConn

		// Start goroutine to relay responses back
		go s.relayUDPResponses(targetConn, relayConn, clientAddr, targetAddr)
	}

	_, err := targetConn.Write(data)
	return err
}

func (s *Server) relayUDPResponses(targetConn *net.UDPConn, relayConn *net.UDPConn, clientAddr *net.UDPAddr, targetAddr string) {
	buf := make([]byte, 65536)
	for {
		n, err := targetConn.Read(buf)
		if err != nil {
			s.logger.Debugf("UDP target connection %s closed: %v", targetAddr, err)
			return
		}

		// Create SOCKS UDP header for response
		targetHost, targetPortStr, err := net.SplitHostPort(targetAddr)
		if err != nil {
			s.logger.Warnf("Invalid target address format %s", targetAddr)
			continue
		}

		targetPortUint, err := strconv.ParseUint(targetPortStr, 10, 16)
		if err != nil {
			s.logger.Warnf("Invalid target port %s", targetPortStr)
			continue
		}
		targetPort := uint16(targetPortUint)

		// Create UDP header
		header := &UDPHeader{
			Reserved: 0,
			Fragment: 0,
			Data:     buf[:n],
			Port:     targetPort,
		}

		// Determine address type and set address
		if ip := net.ParseIP(targetHost); ip != nil {
			if ip.To4() != nil {
				header.AddressType = AddressTypeIPv4
				header.Address = ip.To4()
			} else {
				header.AddressType = AddressTypeIPv6
				header.Address = ip.To16()
			}
		} else {
			header.AddressType = AddressTypeDomain
			header.Address = []byte(targetHost)
		}

		// Serialize and send back to client
		response := s.serializeUDPHeader(header)
		_, err = relayConn.WriteToUDP(response, clientAddr)
		if err != nil {
			s.logger.Warnf("Failed to send UDP response to client: %v", err)
			return
		}
	}
}

func (s *Server) forwardUDPToClient(relayConn *net.UDPConn, clientAddr *net.UDPAddr, _ *net.UDPAddr, data []byte) error {
	// This handles direct UDP packets (not common in typical SOCKS usage)
	_, err := relayConn.WriteToUDP(data, clientAddr)
	return err
}
