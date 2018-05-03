package siren

import "fmt"

// The desired server configuration, which should be passed to Start.
// This controls the behaviour, listening port, private and public keys
// and other behavioural options for the server.
type ServerConfig struct {
	ListenAddress         string
	LocalDomains          []string
	FederationEnabled     bool
	FederationWhitelist   []string
	FederationBlacklist   []string
	MaximumMessageSize    int32
	MaximumS2SConnections int32
	PrivateKey            [cryptoPrivateKeyLen]byte
	PublicKey             [cryptoPublicKeyLen]byte
}

// The Server instance, which contains a number of internal structures
// including the configuration and references to the router and
// directories.
type Server struct {
	config            ServerConfig
	router            router
	externaldirectory directory
	localdirectory    directory
}

// Generates a "default" ServerConfig which can either be used as a
// starting point for your own ServerConfig (recommended), or can be
// passed directly to Start to run with defaults (these defaults may)
// not be incredibly useful.
func DefaultServerConfig() ServerConfig {
	publicKey, privateKey := NewCryptoKeys()
	return ServerConfig{
		ListenAddress:         "0.0.0.0:9989",
		MaximumMessageSize:    4096, // 1048576,
		MaximumS2SConnections: 4096,
		FederationEnabled:     true,
		LocalDomains:          []string{"test.com", "test.net"},
		PublicKey:             *publicKey,
		PrivateKey:            *privateKey,
	}
}

// Starts the server task using the provided ServerConfig. The Start
// function will run (and block) indefinitely.
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
