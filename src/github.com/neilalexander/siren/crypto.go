package siren

import "crypto/rand"
import "errors"

import "github.com/neilalexander/siren/sirenproto"
import proto "github.com/golang/protobuf/proto"
import "golang.org/x/crypto/nacl/box"

// Export these
const cryptoPublicKeyLen = 32
const cryptoPrivateKeyLen = 32

// Don't export these
const cryptoSharedKeyLen = 32
const cryptoNonceLen = 24
const cryptoOverhead = box.Overhead

// Don't export these
type cryptoPublicKey [cryptoPublicKeyLen]byte
type cryptoPrivateKey [cryptoPrivateKeyLen]byte
type cryptoSharedKey [cryptoSharedKeyLen]byte
type cryptoNonce [cryptoNonceLen]byte

func NewCryptoKeys() (*cryptoPublicKey, *cryptoPrivateKey) {
	pubBytes, privBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return (*cryptoPublicKey)(pubBytes), (*cryptoPrivateKey)(privBytes)
}

func EncryptPayload(remotePublicKey cryptoPublicKey, localPrivateKey cryptoPrivateKey, p *sirenproto.Payload) (*sirenproto.EncryptedPayload, error) {
	var nonce [cryptoNonceLen]byte
	message, err := proto.Marshal(p)
	if err != nil {
		return nil, errors.New("Failed to encode packet")
	}

	crypted := make([]byte, 0, len(message)+cryptoOverhead)
	boxed := box.Seal(crypted, message, &nonce,
		(*[32]byte)(&remotePublicKey),
		(*[32]byte)(&localPrivateKey))

	return &sirenproto.EncryptedPayload{
		Ciphertext: boxed,
	}, nil
}

func DecryptPayload(remotePublicKey cryptoPublicKey, localPrivateKey cryptoPrivateKey, p *sirenproto.EncryptedPayload) (*sirenproto.Payload, error) {
	var nonce [cryptoNonceLen]byte
	decrypted := make([]byte, 0, len(p.Ciphertext))
	unboxed, success := box.Open(decrypted, p.Ciphertext, &nonce,
		(*[32]byte)(&remotePublicKey),
		(*[32]byte)(&localPrivateKey))
	if !success {
		return nil, errors.New("Failed to decrypt packet")
	}

	payloadout := &sirenproto.Payload{}
	err := proto.Unmarshal(unboxed, payloadout)
	if err != nil {
		return nil, errors.New("Failed to decode packet")
	}

	return payloadout, nil
}

func (c *connection) EncryptPayload(localPrivateKey cryptoPrivateKey, payload *sirenproto.Payload) (*sirenproto.EncryptedPayload, error) {
	return EncryptPayload(c.remotePublicKey, localPrivateKey, payload)
}

func (c *connection) DecryptPayload(localPrivateKey cryptoPrivateKey, payload *sirenproto.EncryptedPayload) (*sirenproto.Payload, error) {
	return DecryptPayload(c.remotePublicKey, localPrivateKey, payload)
}
