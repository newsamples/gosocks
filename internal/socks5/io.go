package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

func (s *Server) readAuthRequest(conn net.Conn) (*AuthRequest, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	version := buf[0]
	nMethods := buf[1]

	if nMethods == 0 {
		return nil, fmt.Errorf("no authentication methods provided")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}

	return &AuthRequest{
		Version: version,
		Methods: methods,
	}, nil
}

func (s *Server) writeAuthResponse(conn net.Conn, resp *AuthResponse) error {
	buf := []byte{resp.Version, resp.Method}
	_, err := conn.Write(buf)
	return err
}

func (s *Server) readConnectRequest(conn net.Conn) (*ConnectRequest, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	req := &ConnectRequest{
		Version:     buf[0],
		Command:     buf[1],
		Reserved:    buf[2],
		AddressType: buf[3],
	}

	address, port, err := s.readAddress(conn, req.AddressType)
	if err != nil {
		return nil, err
	}

	req.Address = address
	req.Port = port

	return req, nil
}

func (s *Server) readAddress(conn net.Conn, addressType byte) ([]byte, uint16, error) {
	var address []byte
	var err error

	switch addressType {
	case AddressTypeIPv4:
		address = make([]byte, 4)
		if _, err = io.ReadFull(conn, address); err != nil {
			return nil, 0, err
		}

	case AddressTypeIPv6:
		address = make([]byte, 16)
		if _, err = io.ReadFull(conn, address); err != nil {
			return nil, 0, err
		}

	case AddressTypeDomain:
		buf := make([]byte, 1)
		if _, err = io.ReadFull(conn, buf); err != nil {
			return nil, 0, err
		}

		domainLen := buf[0]
		if domainLen == 0 {
			return nil, 0, fmt.Errorf("domain length cannot be zero")
		}

		address = make([]byte, domainLen)
		if _, err = io.ReadFull(conn, address); err != nil {
			return nil, 0, err
		}

	default:
		return nil, 0, ErrInvalidAddressType
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return nil, 0, err
	}

	port := binary.BigEndian.Uint16(portBuf)

	return address, port, nil
}

func (s *Server) writeConnectResponse(conn net.Conn, resp *ConnectResponse) error {
	buf := make([]byte, 4+len(resp.Address)+2)
	buf[0] = resp.Version
	buf[1] = resp.Reply
	buf[2] = resp.Reserved
	buf[3] = resp.AddressType

	copy(buf[4:], resp.Address)
	binary.BigEndian.PutUint16(buf[4+len(resp.Address):], resp.Port)

	_, err := conn.Write(buf)
	return err
}

func (s *Server) parseAddress(req *ConnectRequest) (*Address, error) {
	addr := &Address{
		Type: req.AddressType,
		Port: req.Port,
	}

	switch req.AddressType {
	case AddressTypeIPv4:
		if len(req.Address) != 4 {
			return nil, fmt.Errorf("invalid IPv4 address length")
		}
		addr.IP = net.IP(req.Address)

	case AddressTypeIPv6:
		if len(req.Address) != 16 {
			return nil, fmt.Errorf("invalid IPv6 address length")
		}
		addr.IP = net.IP(req.Address)

	case AddressTypeDomain:
		addr.Host = string(req.Address)

	default:
		return nil, ErrInvalidAddressType
	}

	return addr, nil
}

func (s *Server) encodeAddress(addr net.Addr) (byte, []byte, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, nil, 0, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, nil, 0, err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return AddressTypeDomain, []byte(host), uint16(port), nil
	}

	if ip.To4() != nil {
		return AddressTypeIPv4, ip.To4(), uint16(port), nil
	}

	return AddressTypeIPv6, ip.To16(), uint16(port), nil
}

func (s *Server) parseUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("UDP header too short")
	}

	header := &UDPHeader{
		Reserved: binary.BigEndian.Uint16(data[0:2]),
		Fragment: data[2],
	}

	if header.Fragment != 0 {
		return nil, fmt.Errorf("fragmented UDP packets not supported")
	}

	header.AddressType = data[3]
	offset := 4

	switch header.AddressType {
	case AddressTypeIPv4:
		if len(data) < offset+6 {
			return nil, fmt.Errorf("invalid IPv4 UDP header length")
		}
		header.Address = data[offset : offset+4]
		header.Port = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		offset += 6
	case AddressTypeIPv6:
		if len(data) < offset+18 {
			return nil, fmt.Errorf("invalid IPv6 UDP header length")
		}
		header.Address = data[offset : offset+16]
		header.Port = binary.BigEndian.Uint16(data[offset+16 : offset+18])
		offset += 18
	case AddressTypeDomain:
		if len(data) < offset+1 {
			return nil, fmt.Errorf("invalid domain UDP header length")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return nil, fmt.Errorf("invalid domain UDP header length")
		}
		header.Address = data[offset : offset+domainLen]
		header.Port = binary.BigEndian.Uint16(data[offset+domainLen : offset+domainLen+2])
		offset += domainLen + 2
	default:
		return nil, fmt.Errorf("unsupported address type: %d", header.AddressType)
	}

	header.Data = data[offset:]
	return header, nil
}

func (s *Server) serializeUDPHeader(header *UDPHeader) []byte {
	var buf []byte

	// Reserved (2 bytes) + Fragment (1 byte) + Address Type (1 byte)
	buf = append(buf, 0, 0, 0) // Reserved and Fragment = 0
	buf = append(buf, header.AddressType)

	// Address and Port
	switch header.AddressType {
	case AddressTypeIPv4, AddressTypeIPv6:
		buf = append(buf, header.Address...)
	case AddressTypeDomain:
		buf = append(buf, byte(len(header.Address)))
		buf = append(buf, header.Address...)
	}

	// Port (2 bytes)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, header.Port)
	buf = append(buf, portBytes...)

	// Data
	buf = append(buf, header.Data...)

	return buf
}
