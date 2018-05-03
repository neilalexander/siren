package main

import "net"
import "fmt"
import "bufio"
import "strings"
import "os"
import "strconv"

import "github.com/neilalexander/siren/sirenproto"
import proto "github.com/golang/protobuf/proto"

import "github.com/neilalexander/siren"

func main() {
	var connectionState int
	var remotePublicKey siren.CryptoPublicKey
	publicKey, privateKey := siren.NewCryptoKeys()
	fmt.Println("public key:", *publicKey)
	fmt.Println("private key:", *privateKey)

	conn, err := net.Dial("tcp", "localhost:9989")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	sendPacket(conn, &sirenproto.Payload{
		Contents: &sirenproto.Payload_HelloIAm{
			HelloIAm: &sirenproto.HelloIAm{
				ConnectionType: sirenproto.HelloIAm_CLIENT_TO_SERVER,
				PublicKey:      publicKey[:],
			},
		},
	})

	go func() {
		for {
			buf := make([]byte, 1024)
			buflen, err := conn.Read(buf)

			if err != nil {
				fmt.Println("Error reading packet from server:", err)
				return
			}

			packetin := &sirenproto.Packet{}
			if err := proto.Unmarshal(buf[:buflen], packetin); err != nil {
				fmt.Println("Invalid packet received from server:", err)
				continue
			}

			// Prepare our container!
			var p *sirenproto.Payload

			// If the packet is encrypted, attempt to decrypt it
			switch obj := packetin.PayloadType.(type) {
			case *sirenproto.Packet_EncryptedPayload:
				p, err = siren.DecryptPayload(remotePublicKey, *privateKey, obj.EncryptedPayload)
				if err != nil {
					fmt.Println(err)
					continue
				}
			case *sirenproto.Packet_Payload:
				p = obj.Payload
			}

			switch obj := p.Contents.(type) {
			case *sirenproto.Payload_HelloIAm:
				if connectionState < siren.STATE_AUTHENTICATED {
					copy(remotePublicKey[:32], obj.HelloIAm.PublicKey[:32])
					fmt.Println("Authenticating session")
				}
			case *sirenproto.Payload_Ping:
				fmt.Println("server->client: ping", obj.Ping.Sequence)
				if connectionState < siren.STATE_AUTHENTICATED {
					connectionState = siren.STATE_AUTHENTICATED
					fmt.Println("Authenticated session successfully")
				}
				payloadout := &sirenproto.Payload{
					Contents: &sirenproto.Payload_Pong{
						Pong: &sirenproto.Pong{
							Sequence: obj.Ping.Sequence,
						},
					},
				}
				enc, err := siren.EncryptPayload(remotePublicKey, *privateKey, payloadout)
				if err == nil {
					sendEncryptedPacket(conn, enc)
				}
				fmt.Println("client->server: pong", obj.Ping.Sequence)
			default:
				if connectionState < siren.STATE_AUTHENTICATED {
					continue
				}
				fmt.Println("server->client:", p)
			}
		}
	}()

loop:
	for {
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.Trim(input, " \r\n\t")
		inputtokens := strings.Split(input, " ")

		var payloadout *sirenproto.Payload

		switch inputtokens[0] {
		case "lookup":
			{
				payloadout = &sirenproto.Payload{
					Contents: &sirenproto.Payload_DirectoryRequest{
						DirectoryRequest: &sirenproto.DirectoryRequest{
							UID: inputtokens[1],
						},
					},
				}
			}
		case "ping":
			{
				var seq int64
				if len(inputtokens) > 1 {
					seq, _ = strconv.ParseInt(inputtokens[1], 10, 32)
				}
				payloadout = &sirenproto.Payload{
					Contents: &sirenproto.Payload_Ping{
						Ping: &sirenproto.Ping{
							Sequence: seq,
						},
					},
				}
			}

		case "exit":
			{
				fmt.Println("Exiting")
				break loop
			}
		}

		if connectionState < siren.STATE_AUTHENTICATED {
			sendPacket(conn, payloadout)
		} else {
			enc, err := siren.EncryptPayload(remotePublicKey, *privateKey, payloadout)
			if err == nil {
				sendEncryptedPacket(conn, enc)
			}
		}
	}
}

func sendPacket(conn net.Conn, payload *sirenproto.Payload) {
	packetout := &sirenproto.Packet{
		Version: 1,
		PayloadType: &sirenproto.Packet_Payload{
			Payload: payload,
		},
	}

	if packetout != nil {
		out, err := proto.Marshal(packetout)
		if err != nil {
			fmt.Println("Failed to encode packet:", err)
		}
		if _, err = conn.Write(out); err != nil {
			fmt.Println("Failed to send packet:", err)
		}
	}
}

func sendEncryptedPacket(conn net.Conn, payload *sirenproto.EncryptedPayload) {
	packetout := &sirenproto.Packet{
		Version: 1,
		PayloadType: &sirenproto.Packet_EncryptedPayload{
			EncryptedPayload: payload,
		},
	}

	if packetout != nil {
		out, err := proto.Marshal(packetout)
		if err != nil {
			fmt.Println("Failed to encode packet:", err)
		}
		if _, err = conn.Write(out); err != nil {
			fmt.Println("Failed to send packet:", err)
		}
	}
}
