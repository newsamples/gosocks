package socks5

import (
	"errors"
	"fmt"
	"net"
)

const (
	Socks5Version byte = 0x05

	AuthMethodNoAuth       byte = 0x00
	AuthMethodGSSAPI       byte = 0x01
	AuthMethodUserPass     byte = 0x02
	AuthMethodNoAcceptable byte = 0xFF

	CommandConnect      byte = 0x01
	CommandBind         byte = 0x02
	CommandUDPAssociate byte = 0x03

	AddressTypeIPv4   byte = 0x01
	AddressTypeDomain byte = 0x03
	AddressTypeIPv6   byte = 0x04

	ReplySucceeded               byte = 0x00
	ReplyGeneralFailure          byte = 0x01
	ReplyConnectionNotAllowed    byte = 0x02
	ReplyNetworkUnreachable      byte = 0x03
	ReplyHostUnreachable         byte = 0x04
	ReplyConnectionRefused       byte = 0x05
	ReplyTTLExpired              byte = 0x06
	ReplyCommandNotSupported     byte = 0x07
	ReplyAddressTypeNotSupported byte = 0x08
)

var (
	ErrInvalidVersion     = errors.New("invalid SOCKS version")
	ErrInvalidCommand     = errors.New("invalid command")
	ErrInvalidAddressType = errors.New("invalid address type")
	ErrAuthFailed         = errors.New("authentication failed")
	ErrNoAcceptableAuth   = errors.New("no acceptable authentication methods")
)

type AuthRequest struct {
	Version byte
	Methods []byte
}

type AuthResponse struct {
	Version byte
	Method  byte
}

type ConnectRequest struct {
	Version     byte
	Command     byte
	Reserved    byte
	AddressType byte
	Address     []byte
	Port        uint16
}

type ConnectResponse struct {
	Version     byte
	Reply       byte
	Reserved    byte
	AddressType byte
	Address     []byte
	Port        uint16
}

type Address struct {
	Type byte
	Host string
	Port uint16
	IP   net.IP
}

type UDPHeader struct {
	Reserved    uint16
	Fragment    byte
	AddressType byte
	Address     []byte
	Port        uint16
	Data        []byte
}

func (a *Address) String() string {
	portStr := fmt.Sprintf("%d", a.Port)
	if a.Type == AddressTypeIPv4 || a.Type == AddressTypeIPv6 {
		return net.JoinHostPort(a.IP.String(), portStr)
	}
	return net.JoinHostPort(a.Host, portStr)
}

func (a *Address) Network() string {
	return "tcp"
}
