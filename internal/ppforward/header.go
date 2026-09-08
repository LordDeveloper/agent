package ppforward

import (
	"errors"
	"fmt"
	"net"
)

// FormatProxyHeaderV1 builds an HAProxy PROXY protocol v1 line for IPv4 TCP.
func FormatProxyHeaderV1(clientAddr, serverAddr *net.TCPAddr) ([]byte, error) {
	if clientAddr == nil || serverAddr == nil {
		return nil, errors.New("addresses are required")
	}

	clientIP := clientAddr.IP.To4()
	if clientIP == nil {
		return nil, errors.New("client address must be IPv4")
	}

	serverIP := serverAddr.IP.To4()
	if serverIP == nil {
		serverIP = net.IPv4(127, 0, 0, 1).To4()
	}

	line := fmt.Sprintf(
		"PROXY TCP4 %s %s %d %d\r\n",
		clientIP.String(),
		serverIP.String(),
		clientAddr.Port,
		serverAddr.Port,
	)
	return []byte(line), nil
}
