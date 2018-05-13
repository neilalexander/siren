package siren

import "fmt"
import "net"
import "time"
import "reflect"
import "strings"
import "bytes"

import "github.com/neilalexander/siren/sirenproto"
import proto "github.com/golang/protobuf/proto"

const (
	STATE_INITIAL        = iota
	STATE_AUTHENTICATING = iota
	STATE_AUTHENTICATED  = iota
)

type connection struct {
	state            int
	remotePublicKey  [cryptoPublicKeyLen]byte
	pingSequence     int64
	pingLastResponse time.Time
	connection       net.Conn
	connectionType   sirenproto.HelloIAm_ConnectionTypes
	writeEncrypted   chan *sirenproto.Payload
	writeUnencrypted chan *sirenproto.Payload
	terminateWrite   chan bool
	writeTicker      *time.Ticker
	federationDomain string
}

func (c *connection) writeThread(r *router, initiator bool) {
	c.terminateWrite = make(chan bool)
	c.writeTicker = time.NewTicker(time.Second)
	defer c.writeTicker.Stop()
	if len(c.federationDomain) > 0 {
		defer delete(r.server.router.federations, c.federationDomain)
	}

	// If we are the initiator of the connection then the first thing we
	// need to do is introduce ourself to the remote side - this includes
	// sending our public key and requesting an S2S-type connection
	if initiator {
		c.state = STATE_AUTHENTICATING
		c.writeUnencrypted <- &sirenproto.Payload{
			Contents: &sirenproto.Payload_HelloIAm{
				HelloIAm: &sirenproto.HelloIAm{
					ConnectionType: sirenproto.HelloIAm_SERVER_TO_SERVER,
					PublicKey:      r.server.config.PublicKey[:],
				},
			},
		}
	}

	// Start listening for packets to send to the connection. Each message
	// arrives through either the encrypted or the unencrypted channel
	for {
		select {
		case _ = <-c.terminateWrite:
			// The read thread asked the write thread to stop processing
			return
		case payload := <-c.writeUnencrypted:
			// We received a payload to be sent unencrypted - wrap it in the
			// packet format and send it to the remote side
			packet := sirenproto.Packet{
				Version: 1,
				PayloadType: &sirenproto.Packet_Payload{
					Payload: payload,
				},
			}
			c.send(&packet)
		case payload := <-c.writeEncrypted:
			// We received a payload to be sent encrypted, so first of all we
			// need to check if the connection is authenticated. If not then we
			// can't do anything
			// TODO: Can we queue these packets for later dispatch?
			switch payload.Contents.(type) {
			case *sirenproto.Payload_Ping:
				// As long as we know the public key, we are happy to send pings
				// on unauthenticated sessions because a successful ping-pong
				// exchange is part of the handshake
				break
			default:
				// If it's not a ping then we musn't try to send it over an
				// unauthenticated session
				if c.state < STATE_AUTHENTICATED {
					continue
				}
			}
			// Encrypt the payload and then wrap it in the packet format, send
			// it to the remote side
			enc, err := c.EncryptPayload(r.server.config.PrivateKey, payload)
			if err == nil {
				packet := sirenproto.Packet{
					Version: 1,
					PayloadType: &sirenproto.Packet_EncryptedPayload{
						EncryptedPayload: enc,
					},
				}
				c.send(&packet)
			} else {
				fmt.Println(err)
			}
		case <-c.writeTicker.C:
			// The ticker fires on an interval, and is used to send pings to the
			// remote side
			c.writeEncrypted <- &sirenproto.Payload{
				Contents: &sirenproto.Payload_Ping{
					Ping: &sirenproto.Ping{
						Sequence: c.pingSequence,
					},
				},
			}
			c.pingSequence++
			// Have we failed to authenticate with the remote side after a
			// given number of pings? If so, decrease the interval and stop
			// spamming the remote side so much
			if c.pingSequence == 30 {
				if c.state < STATE_AUTHENTICATED {
					fmt.Println("Remote side hasn't authenticated in 30 seconds")
					c.writeTicker.Stop()
					c.writeTicker = time.NewTicker(time.Minute)
				}
			}
		}
	}
}

func (c *connection) readThread(r *router, initiator bool) {
	fmt.Println("Opened connection with", c.connection.RemoteAddr())
	defer c.connection.Close()

	buf := make([]byte, r.server.config.MaximumMessageSize)

loop:
	for {
		buflen, err := c.connection.Read(buf)
		if err != nil {
			break loop
		}

		// Attempt to decode the protobuf packet we received. If it isn't
		// possible to decode the packet then send back a warning and drop
		// the connection.
		packetin := &sirenproto.Packet{}
		if err := proto.Unmarshal(buf[:buflen], packetin); err != nil {
			c.writeEncrypted <- &sirenproto.Payload{
				Contents: &sirenproto.Payload_Ack{
					Ack: &sirenproto.Ack{
						Condition: sirenproto.Ack_TERMINATE,
						Text:      "Failed to decode packet",
					},
				},
			}
			fmt.Printf("Could not decode packet:\n----\n\x1b[31m%s\x1b[39m\n----\n", buf[:buflen])
			break loop
		}

		var payload *sirenproto.Payload
		var wasEncrypted bool

		// First of all we need to determine whether the packet we received
		// is a standard unencrypted payload, or an encrypted one.
		switch received := packetin.PayloadType.(type) {
		case *sirenproto.Packet_EncryptedPayload:
			// The received packet was encrypted, therefore decrypt it
			payload, err = c.DecryptPayload(r.server.config.PrivateKey, received.EncryptedPayload)
			if err != nil {
				fmt.Println(err)
				continue
			}
			wasEncrypted = true
		case *sirenproto.Packet_Payload:
			// The received packet wasn't encrypted so nothing needs to be done
			payload = received.Payload
			wasEncrypted = false
		default:
			// The payload type isn't known - send a warning back
			c.writeEncrypted <- &sirenproto.Payload{
				Contents: &sirenproto.Payload_Ack{
					Ack: &sirenproto.Ack{
						Condition: sirenproto.Ack_INVALID_PACKET,
						Text:      "Unknown payload type",
					},
				},
			}
		}

		// The behaviour for encrypted and decrypted packets is different -
		// in this instance we expect a "HelloIAm" packet to be unencrypted
		// but we expect all other packet types to be encrypted
		if !wasEncrypted {
			// We received an unencrypted packet
			switch received := payload.Contents.(type) {
			case *sirenproto.Payload_HelloIAm:
				// Only accept federation connections from other servers if
				// federation is enabled in the server config
				if received.HelloIAm.ConnectionType == sirenproto.HelloIAm_SERVER_TO_SERVER {
					if !r.server.config.FederationEnabled {
						// Federation is not enabled. Goodbye!
						c.writeEncrypted <- &sirenproto.Payload{
							Contents: &sirenproto.Payload_Ack{
								Ack: &sirenproto.Ack{
									Condition: sirenproto.Ack_TERMINATE,
									Text:      "This server does not accept federation",
								},
							},
						}
						break loop
					}
				}
				// Make sure that we aren't connecting to ourselves. This shouldn't
				// ever really happen, but stranger things happen at sea
				if bytes.Equal(received.HelloIAm.PublicKey[:32], r.server.config.PublicKey[:32]) {
					fmt.Println("Rejecting connection from same public key")
					c.writeEncrypted <- &sirenproto.Payload{
						Contents: &sirenproto.Payload_Ack{
							Ack: &sirenproto.Ack{
								Condition: sirenproto.Ack_TERMINATE,
								Text:      "Rejecting connection from same public key",
							},
						},
					}
					// break loop
				}
				// If the connection wasn't authenticated before this point then
				// store the public key and connection type and mark the connection
				// as authenticated. This allows encrypted traffic to be sent and
				// received from this point forward
				if c.state < STATE_AUTHENTICATED {
					copy(c.remotePublicKey[:32], received.HelloIAm.PublicKey[:32])
					c.connectionType = received.HelloIAm.ConnectionType
				}
				// If we were the initiator of the connection then we have already
				// sent our "HelloIAm" packet already in the write thread, so only
				// send a response "HelloIAm" if we are not the initiator
				if !initiator {
					c.writeUnencrypted <- &sirenproto.Payload{
						Contents: &sirenproto.Payload_HelloIAm{
							HelloIAm: &sirenproto.HelloIAm{
								ConnectionType: received.HelloIAm.ConnectionType,
								PublicKey:      r.server.config.PublicKey[:],
							},
						},
					}
				}
			default:
				// This case happens if we've received an unencrypted packet that
				// isn't defined above. If that happens then send an error back
				// to the sender telling them that encryption is required for
				// that payload type
				c.writeUnencrypted <- &sirenproto.Payload{
					Contents: &sirenproto.Payload_Ack{
						Ack: &sirenproto.Ack{
							Condition: sirenproto.Ack_REQUIRES_ENCRYPTION,
							Text:      fmt.Sprintf("%v", reflect.TypeOf(received)),
						},
					},
				}
			}
		} else {
			// We received an encrypted packet. If our session is not already
			// marked as authenticated then now we can safely do that
			if c.state < STATE_AUTHENTICATED {
				fmt.Println("Connection authenticated")
				c.state = STATE_AUTHENTICATED
				c.writeTicker.Stop()
				c.writeTicker = time.NewTicker(time.Minute)
			}

			// Process the packet
			switch received := payload.Contents.(type) {
			case *sirenproto.Payload_Ping:
				// If we receive a ping from the remote side then we should respond
				// with a pong. The connection must have been authenticated for
				// pings and pongs to be exchanged
				fmt.Println("Received ping from", c.connection.RemoteAddr())
				c.writeEncrypted <- &sirenproto.Payload{
					Contents: &sirenproto.Payload_Pong{
						Pong: &sirenproto.Pong{
							Sequence: received.Ping.Sequence,
						},
					},
				}
			case *sirenproto.Payload_Pong:
				// The write thread also sends periodic pings to open connections.
				// If we receive a pong then we should do nothing but store the
				// last time we received a pong. This acts as a bit of a keep-alive
				// for peer connections and lets us identify dead connections
				c.pingLastResponse = time.Now()
				fmt.Println("Last pong response:", c.pingLastResponse)
				continue
			case *sirenproto.Payload_DirectoryRequest:
				// A directory request happens when a client wants to look up the
				// user signing keys (USK) or device encryption keys (DEK) for a
				// given user ID. First of all determine if the UID is one that
				// we serve locally, or we need to go externally for
				fmt.Println("Directory request for " + received.DirectoryRequest.UID)
				parts := strings.Split(strings.Trim(received.DirectoryRequest.UID, " \t\r\n"), "@")
				if len(parts) != 2 {
					fmt.Println("Invalid UID")
					break
				}
				// Check if we have a local directory for this domain, otherwise
				// use the "external" directory which caches records from outside servers
				directory := r.server.externaldirectory
				for _, domain := range r.server.config.LocalDomains {
					if domain == parts[1] {
						directory = r.server.localdirectory
					}
				}
				// Create the request and create a channel to wait for the response.
				// This thread will wait for the response before sending it to the
				// remote side
				rc := make(chan sirenproto.DirectoryResponse)
				go directory.directoryRequest(*received.DirectoryRequest, rc)
				// Wait for a response from the directory and send it back to the
				// remote requestor
				response := <-rc
				c.writeEncrypted <- &sirenproto.Payload{
					Contents: &sirenproto.Payload_DirectoryResponse{
						DirectoryResponse: &response,
					},
				}
			default:
				// We received an authenticated but unrecognised packet - this isn't
				// necessarily catastrophic as it might just be a new packet type
				// so the connection isn't terminated when this happens
				fmt.Println("Unknown packet type")
				c.writeEncrypted <- &sirenproto.Payload{
					Contents: &sirenproto.Payload_Ack{
						Ack: &sirenproto.Ack{
							Condition: sirenproto.Ack_INVALID_PACKET,
							Text:      "Unknown packet type",
						},
					},
				}
			}
		}
	}

	// If we reach this point then we want the connection to be dropped
	c.terminateWrite <- true
	fmt.Println("Closed connection with", c.connection.RemoteAddr())
}

func (c *connection) send(packet *sirenproto.Packet) {
	// Marshalling turns the packet from the Protobuf struct into binary
	// format to write out onto the wire. If there is an error marshalling
	// then just drop the packet
	out, err := proto.Marshal(packet)
	if err != nil {
		fmt.Println("Failed to encode packet:", err)
		return
	}
	if _, err = c.connection.Write(out); err != nil {
		// Check for actual connection errors on the socket
		switch err.(type) {
		case *net.OpError:
			return
		default:
			fmt.Println("Failed to send packet:", err)
		}
	}
}
