package main

import "github.com/neilalexander/siren"

func main() {
	var server siren.Server
	server.Start(siren.DefaultServerConfig())
}
