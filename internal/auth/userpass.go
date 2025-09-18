package auth

import (
	"fmt"
	"io"
	"net"
)

const (
	UserPassVersion   = 0x01
	AuthStatusSuccess = 0x00
	AuthStatusFailure = 0x01
)

type UserPassAuthenticator struct {
	credentials map[string]string
}

type UserPassRequest struct {
	Version  byte
	Username string
	Password string
}

type UserPassResponse struct {
	Version byte
	Status  byte
}

func NewUserPassAuthenticator(credentials map[string]string) *UserPassAuthenticator {
	return &UserPassAuthenticator{
		credentials: credentials,
	}
}

func (u *UserPassAuthenticator) Authenticate(conn net.Conn, method byte) error {
	if method != 0x02 {
		return fmt.Errorf("unsupported authentication method: %d", method)
	}

	req, err := u.readUserPassRequest(conn)
	if err != nil {
		return err
	}

	if req.Version != UserPassVersion {
		return fmt.Errorf("invalid username/password version: %d", req.Version)
	}

	status := AuthStatusFailure
	if password, exists := u.credentials[req.Username]; exists && password == req.Password {
		status = AuthStatusSuccess
	}

	resp := &UserPassResponse{
		Version: UserPassVersion,
		Status:  byte(status),
	}

	if err := u.writeUserPassResponse(conn, resp); err != nil {
		return err
	}

	if status != AuthStatusSuccess {
		return fmt.Errorf("authentication failed for user: %s", req.Username)
	}

	return nil
}

func (u *UserPassAuthenticator) GetMethods() []byte {
	return []byte{0x02}
}

func (u *UserPassAuthenticator) readUserPassRequest(conn net.Conn) (*UserPassRequest, error) {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	version := buf[0]

	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	usernameLen := buf[0]

	if usernameLen == 0 {
		return nil, fmt.Errorf("username length cannot be zero")
	}

	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	passwordLen := buf[0]

	password := make([]byte, passwordLen)
	if passwordLen > 0 {
		if _, err := io.ReadFull(conn, password); err != nil {
			return nil, err
		}
	}

	return &UserPassRequest{
		Version:  version,
		Username: string(username),
		Password: string(password),
	}, nil
}

func (u *UserPassAuthenticator) writeUserPassResponse(conn net.Conn, resp *UserPassResponse) error {
	buf := []byte{resp.Version, resp.Status}
	_, err := conn.Write(buf)
	return err
}
