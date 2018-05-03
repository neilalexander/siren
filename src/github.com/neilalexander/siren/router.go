package siren

import "fmt"
import "net"
import "os"

import "github.com/neilalexander/siren/sirenproto"

type router struct {
	server      *Server
	listener    net.Listener
	connections []connection
	federations map[string]connection
	in          chan *sirenproto.Payload
}

func (r *router) start(s *Server) {
	fmt.Println("Starting router")

	r.server = s
	r.connections = make([]connection, r.server.config.MaximumS2SConnections)
	r.federations = make(map[string]connection)
	r.in = make(chan *sirenproto.Payload)

	go r.listenForConnections()
}

func (r *router) listenForConnections() {
	// Start listening for connections
	var err error
	r.listener, err = net.Listen("tcp", r.server.config.ListenAddress)
	if err != nil {
		fmt.Println("Error listening on", r.server.config.ListenAddress, err.Error())
		os.Exit(1)
	}

	// At this point the connection has been successfully opened so
	// defer our closure until later
	defer r.listener.Close()
	fmt.Println("Listening on", r.server.config.ListenAddress)

	for {
		// Wait for a new connection to come in
		conn, err := r.listener.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// We've received a new connection - we need to create a new
		// connection object with the appropriate channels so that the
		// read and write threads know where the socket connection is
		connection := &connection{
			connection:       conn,
			writeEncrypted:   make(chan *sirenproto.Payload, 10),
			writeUnencrypted: make(chan *sirenproto.Payload, 10),
		}
		// Store the connection in the connections table
		r.connections = append(r.connections, *connection)
		// Start the read and write threads
		go connection.writeThread(r, false)
		go connection.readThread(r, false)
	}
}

func (r *router) initiateOutgoingConnection(domain string) {
	// Let's see if we already have a federation connection open
	// for this domain - if we do then we don't need to open
	// another one
	if _, ok := r.federations[domain]; ok {
		return
	}

	// Look up the _siren._tcp.hostname.com DNS SRV record - this
	// will tell us where we can find the remote server
	_, addr, err := net.LookupSRV("siren", "tcp", domain)
	if err != nil {
		fmt.Println("Error in DNS SRV lookup")
	}

	// For each record that was returned, try to connect to it
	for _, a := range addr {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", a.Target, a.Port))
		if err != nil {
			fmt.Println("Unable to connect to federation target", a.Target)
		} else {
			fmt.Println("Connected to federation target", a.Target)

			// We've successfully connected to the remote side - create a new
			// connection object and add it to the connections table
			connection := &connection{
				connection:       conn,
				writeEncrypted:   make(chan *sirenproto.Payload, 10),
				writeUnencrypted: make(chan *sirenproto.Payload, 10),
				federationDomain: domain,
			}
			r.connections = append(r.connections, *connection)
			r.federations[domain] = *connection

			// Start the read and write threads for the new connection
			go connection.writeThread(r, true)
			go connection.readThread(r, true)

			// At this point we've been successful in finding a server to
			// connect to, so we can stop trying
			break
		}
	}
}
