package config

import (
	"errors"
	"time"

	"github.com/vitalvas/gokit/xconfig"
)

type Config struct {
	Server ServerConfig `yaml:"server" json:"server"`
	Auth   AuthConfig   `yaml:"auth" json:"auth"`
	Log    LogConfig    `yaml:"log" json:"log"`
}

type ServerConfig struct {
	BindAddress    string        `yaml:"bind_address" json:"bind_address" default:"0.0.0.0:1080"`
	ConnectTimeout time.Duration `yaml:"connect_timeout" json:"connect_timeout" default:"30s"`
	ReadTimeout    time.Duration `yaml:"read_timeout" json:"read_timeout" default:"30s"`
	WriteTimeout   time.Duration `yaml:"write_timeout" json:"write_timeout" default:"30s"`
	EnableIPv6GW   bool          `yaml:"enable_ipv6_gateway" json:"enable_ipv6_gateway" default:"false"`
}

type AuthConfig struct {
	Enable bool             `yaml:"enable" json:"enable" default:"false"`
	Users  []UserCredential `yaml:"users" json:"users"`
}

type UserCredential struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type LogConfig struct {
	Level string `yaml:"level" json:"level" default:"info"`
}

func Load(configPath string) (*Config, error) {
	var cfg Config

	options := []xconfig.Option{
		xconfig.WithEnv("GOSOCKS"),
	}

	if configPath != "" {
		options = append(options, xconfig.WithFiles(configPath))
	}

	if err := xconfig.Load(&cfg, options...); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if !c.Auth.Enable {
		return nil
	}

	// Check if we have any authentication credentials configured
	hasCredentials := len(c.Auth.Users) > 0
	if hasCredentials {
		// Validate that all users have both username and password
		for i, user := range c.Auth.Users {
			if user.Username == "" || user.Password == "" {
				return errors.New("all users must have both username and password")
			}
			// Check for duplicate usernames
			for j := i + 1; j < len(c.Auth.Users); j++ {
				if user.Username == c.Auth.Users[j].Username {
					return errors.New("duplicate username found: " + user.Username)
				}
			}
		}
	}

	if !hasCredentials {
		return errors.New("authentication is enabled but no valid credentials configured")
	}

	return nil
}

// GetCredentials returns a map of all configured credentials
func (c *Config) GetCredentials() map[string]string {
	credentials := make(map[string]string)

	// Add array-based users
	for _, user := range c.Auth.Users {
		if user.Username != "" && user.Password != "" {
			credentials[user.Username] = user.Password
		}
	}

	return credentials
}
