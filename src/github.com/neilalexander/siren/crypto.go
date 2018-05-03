package siren

import "crypto/rand"
import "errors"

import "github.com/neilalexander/siren/sirenproto"
import proto "github.com/golang/protobuf/proto"
import "golang.org/x/crypto/nacl/box"

const CryptoPublicKeyLen = 32
const CryptoPrivateKeyLen = 32
const CryptoSharedKeyLen = 32
const CryptoNonceLen = 24
const CryptoOverhead = box.Overhead

type CryptoPublicKey [CryptoPublicKeyLen]byte
type CryptoPrivateKey [CryptoPrivateKeyLen]byte
type CryptoSharedKey [CryptoSharedKeyLen]byte
type CryptoNonce [CryptoNonceLen]byte

func NewCryptoKeys() (*CryptoPublicKey, *CryptoPrivateKey) {
	pubBytes, privBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return (*CryptoPublicKey)(pubBytes), (*CryptoPrivateKey)(privBytes)
}

func EncryptPayload(remotePublicKey CryptoPublicKey, localPrivateKey CryptoPrivateKey, p *sirenproto.Payload) (*sirenproto.EncryptedPayload, error) {
	var nonce [CryptoNonceLen]byte
	message, err := proto.Marshal(p)
	if err != nil {
		return nil, errors.New("Failed to encode packet")
	}

	crypted := make([]byte, 0, len(message)+CryptoOverhead)
	boxed := box.Seal(crypted, message, &nonce,
		(*[32]byte)(&remotePublicKey),
		(*[32]byte)(&localPrivateKey))

	return &sirenproto.EncryptedPayload{
		Ciphertext: boxed,
	}, nil
}

func DecryptPayload(remotePublicKey CryptoPublicKey, localPrivateKey CryptoPrivateKey, p *sirenproto.EncryptedPayload) (*sirenproto.Payload, error) {
	var nonce [CryptoNonceLen]byte
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

func (c *connection) EncryptPayload(localPrivateKey CryptoPrivateKey, payload *sirenproto.Payload) (*sirenproto.EncryptedPayload, error) {
	return EncryptPayload(c.remotePublicKey, localPrivateKey, payload)
}

func (c *connection) DecryptPayload(localPrivateKey CryptoPrivateKey, payload *sirenproto.EncryptedPayload) (*sirenproto.Payload, error) {
	return DecryptPayload(c.remotePublicKey, localPrivateKey, payload)
}
