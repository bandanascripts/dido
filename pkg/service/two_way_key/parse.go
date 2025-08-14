package twowaykey

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/bandanascripts/dido/pkg/service/redis"
	goRedis "github.com/redis/go-redis/v9"
)

func PemDecPrivKey(strPrivateKey string) ([]byte, error) {

	block, _ := pem.Decode([]byte(strPrivateKey))

	if block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("invalid type")
	}

	return block.Bytes, nil

}

func PemDecPubKey(strPublicKey string) ([]byte, error) {

	block, _ := pem.Decode([]byte(strPublicKey))

	if block.Type != "EC PUBLIC KEY" {
		return nil, errors.New("invalid type")
	}

	return block.Bytes, nil

}

func ParsePrivKey(bytePrivateKey []byte) (*ecdsa.PrivateKey, error) {

	privateKey, err := x509.ParseECPrivateKey(bytePrivateKey)

	if err != nil { 
		return nil, err }

	return privateKey, nil

}

func ParsePubKey(bytePublicKey []byte) (*ecdsa.PublicKey, error) {

	publicKeyIface, err := x509.ParsePKIXPublicKey(bytePublicKey)

	if err != nil { 
		return nil, err }

	publicKey, ok := publicKeyIface.(*ecdsa.PublicKey)

	if !ok {
		return nil, errors.New("missing public key")
	}

	return publicKey, nil

}

func FetchPrivKeyFromRedis(redCli *goRedis.Client, ctx context.Context, privateKeyId string) (*ecdsa.PrivateKey, error) {

	strPrivateKey, err := redis.GetFromRedis(redCli, ctx, privateKeyId)

	if err != nil { 
		return nil, err }

	bytePrivateKey, err := PemDecPrivKey(strPrivateKey)

	if err != nil { 
		return nil, err }

	privateKey, err := ParsePrivKey(bytePrivateKey)

	if err != nil { 
		return nil, err }

	return privateKey, nil

}

func FetchPubKeyFromRedis(redCli *goRedis.Client, ctx context.Context, publicKeyId string) (*ecdsa.PublicKey, error) {

	strPublicKey, err := redis.GetFromRedis(redCli, ctx, publicKeyId)

	if err != nil { 
		return nil, err }

	bytePublicKey, err := PemDecPubKey(strPublicKey)

	if err != nil { 
		return nil, err }

	publicKey, err := ParsePubKey(bytePublicKey)

	if err != nil { 
		return nil, err }

	return publicKey, nil

}
