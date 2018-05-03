package siren

import "fmt"

type ServerConfig struct {
	ListenAddress         string
	LocalDomains          []string
	FederationEnabled     bool
	FederationWhitelist   []string
	FederationBlacklist   []string
	MaximumMessageSize    int32
	MaximumS2SConnections int32
	PrivateKey            [CryptoPrivateKeyLen]byte
	PublicKey             [CryptoPublicKeyLen]byte
}

type Server struct {
	config            ServerConfig
	router            router
	externaldirectory directory
	localdirectory    directory
}

func DefaultServerConfig() ServerConfig {
	publicKey, privateKey := NewCryptoKeys()
	return ServerConfig{
		ListenAddress:         "0.0.0.0:9989",
		MaximumMessageSize:    4096, // 1048576,
		MaximumS2SConnections: 4096,
		FederationEnabled:     false,
		LocalDomains:          []string{"test.com", "test.net"},
		PublicKey:             *publicKey,
		PrivateKey:            *privateKey,
	}
}

func (s *Server) Start(c ServerConfig) {
	fmt.Println("Starting server")
	fmt.Println("Public key:", c.PublicKey)
	fmt.Println("Private key:", c.PrivateKey)

	s.config = c
	s.router.start(s)

	s.externaldirectory.start(s)
	s.localdirectory.start(s, s.config.LocalDomains...)

	for {
	}
}
