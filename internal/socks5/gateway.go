package socks5

import (
	"fmt"
	"net"
	"strings"
)

type GatewayConfig struct {
	EnableIPv4ToIPv6 bool
	EnableIPv6ToIPv4 bool
	IPv6Prefix       string
	IPv4Subnet       string
}

type Gateway struct {
	config     *GatewayConfig
	ipv6Prefix net.IP
	ipv4Subnet *net.IPNet
}

func NewGateway(config *GatewayConfig) (*Gateway, error) {
	gw := &Gateway{
		config: config,
	}

	if config.EnableIPv4ToIPv6 && config.IPv6Prefix != "" {
		prefix := net.ParseIP(config.IPv6Prefix)
		if prefix == nil {
			return nil, fmt.Errorf("invalid IPv6 prefix: %s", config.IPv6Prefix)
		}
		gw.ipv6Prefix = prefix
	}

	if config.EnableIPv6ToIPv4 && config.IPv4Subnet != "" {
		_, subnet, err := net.ParseCIDR(config.IPv4Subnet)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv4 subnet: %s", config.IPv4Subnet)
		}
		gw.ipv4Subnet = subnet
	}

	return gw, nil
}

func (g *Gateway) TranslateAddress(addr *Address) (*Address, error) {
	if addr.Type == AddressTypeIPv4 && g.config.EnableIPv4ToIPv6 {
		return g.translateIPv4ToIPv6(addr)
	}

	if addr.Type == AddressTypeIPv6 && g.config.EnableIPv6ToIPv4 {
		return g.translateIPv6ToIPv4(addr)
	}

	return addr, nil
}

func (g *Gateway) translateIPv4ToIPv6(addr *Address) (*Address, error) {
	if g.ipv6Prefix == nil {
		return addr, nil
	}

	ipv4 := addr.IP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	ipv6 := make(net.IP, 16)
	copy(ipv6[:12], g.ipv6Prefix[:12])
	copy(ipv6[12:], ipv4)

	return &Address{
		Type: AddressTypeIPv6,
		IP:   ipv6,
		Port: addr.Port,
	}, nil
}

func (g *Gateway) translateIPv6ToIPv4(addr *Address) (*Address, error) {
	if g.ipv4Subnet == nil {
		return addr, nil
	}

	ipv6 := addr.IP.To16()
	if ipv6 == nil {
		return nil, fmt.Errorf("invalid IPv6 address")
	}

	if !g.isIPv4MappedIPv6(ipv6) {
		return addr, nil
	}

	ipv4 := ipv6[12:]

	if !g.ipv4Subnet.Contains(ipv4) {
		return addr, nil
	}

	return &Address{
		Type: AddressTypeIPv4,
		IP:   ipv4,
		Port: addr.Port,
	}, nil
}

func (g *Gateway) isIPv4MappedIPv6(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}

	for i := 0; i < 10; i++ {
		if ip[i] != 0 {
			return false
		}
	}

	return ip[10] == 0xff && ip[11] == 0xff
}

func (g *Gateway) ResolveAddress(addr *Address) (string, error) {
	translatedAddr, err := g.TranslateAddress(addr)
	if err != nil {
		return "", err
	}

	switch translatedAddr.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		return net.JoinHostPort(translatedAddr.IP.String(), fmt.Sprintf("%d", translatedAddr.Port)), nil
	case AddressTypeDomain:
		return net.JoinHostPort(translatedAddr.Host, fmt.Sprintf("%d", translatedAddr.Port)), nil
	default:
		return "", fmt.Errorf("unsupported address type: %d", translatedAddr.Type)
	}
}

func (g *Gateway) SupportsDualStack() bool {
	return g.config.EnableIPv4ToIPv6 || g.config.EnableIPv6ToIPv4
}

func (g *Gateway) GetPreferredNetwork(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "tcp"
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "tcp"
	}

	if ip.To4() != nil && g.config.EnableIPv4ToIPv6 {
		return "tcp6"
	}

	if ip.To4() == nil && g.config.EnableIPv6ToIPv4 {
		return "tcp4"
	}

	return "tcp"
}

func (g *Gateway) IsIPv6Address(addr string) bool {
	return strings.Contains(addr, ":")
}

func (g *Gateway) IsIPv4Address(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() != nil
}
