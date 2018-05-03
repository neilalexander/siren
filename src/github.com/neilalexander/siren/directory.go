package siren

import "fmt"
import "time"
import "strings"

import "github.com/neilalexander/siren/sirenproto"

type userSigningKey struct {
	publicKey []byte
}

type deviceEncryptionKey struct {
	publicKeys [][]byte
	lastSeen   time.Time
}

type directory struct {
	server *Server

	isLocalDirectory bool
	localDomains     []string

	// TODO: It would be better to map UID->USK and then USK->DEK
	mapUIDtoUSK map[string]userSigningKey
	mapUIDtoDEK map[string]deviceEncryptionKey
}

func (d *directory) start(s *Server, domains ...string) {
	d.server = s

	// Create our USK and DEK maps
	// TODO: It would be better to map UID->USK and then USK->DEK
	d.mapUIDtoUSK = make(map[string]userSigningKey)
	d.mapUIDtoDEK = make(map[string]deviceEncryptionKey)

	// Determine if we have been given any local domains to serve
	if len(domains) > 0 {
		fmt.Println("Starting directory for domains", domains)
		d.isLocalDirectory = true
		d.localDomains = domains

		// Generate some keys for test@test.com
		pk1, _ := NewCryptoKeys()
		pk2, _ := NewCryptoKeys()
		pk3, _ := NewCryptoKeys()

		// Map the keys
		d.mapUIDtoUSK["test@test.com"] = userSigningKey{
			publicKey: (*pk1)[:],
		}
		d.mapUIDtoDEK["test@test.com"] = deviceEncryptionKey{
			publicKeys: [][]byte{(*pk2)[:], (*pk3)[:]},
		}
	} else {
		fmt.Println("Starting directory for external caching")
		d.isLocalDirectory = false
	}
}

func (d *directory) directoryRequest(r sirenproto.DirectoryRequest, c chan sirenproto.DirectoryResponse) {
	// Look up the appropriate function for the type of directory
	if d.isLocalDirectory {
		c <- d.directoryRequestInternal(r)
	} else {
		c <- d.directoryRequestExternal(r)
	}
}

func (d *directory) directoryRequestInternal(r sirenproto.DirectoryRequest) sirenproto.DirectoryResponse {
	// Create the directory response object based on the USK and DEK maps
	return sirenproto.DirectoryResponse{
		UID:                 r.UID,
		UserSigningKey:      d.mapUIDtoUSK[r.UID].publicKey,
		DeviceEncryptionKey: d.mapUIDtoDEK[r.UID].publicKeys,
	}
}

func (d *directory) directoryRequestExternal(r sirenproto.DirectoryRequest) sirenproto.DirectoryResponse {
	// Extract the domain part
	parts := strings.Split(strings.Trim(r.UID, " \t\r\n"), "@")
	if len(parts) != 2 {
		fmt.Println("Invalid UID")
		return sirenproto.DirectoryResponse{}
	}

	// Create a connection if needed to the remote server
	d.server.router.initiateOutgoingConnection(parts[1])

	// Create the directory response object based on the USK and DEK maps
	return sirenproto.DirectoryResponse{
		UID:                 r.UID,
		UserSigningKey:      d.mapUIDtoUSK[r.UID].publicKey,
		DeviceEncryptionKey: d.mapUIDtoDEK[r.UID].publicKeys,
	}
}
