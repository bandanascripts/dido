package twowaykey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/bandanascripts/dido/pkg/service/redis"
	goRedis "github.com/redis/go-redis/v9"
)

func GenerateKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil { return nil, nil, err }

	return privateKey, &privateKey.PublicKey, nil

}

func MarshalPrivKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {

	bytePrivateKey, err := x509.MarshalECPrivateKey(privateKey)

	if err != nil { return nil, err }

	return bytePrivateKey, nil

}

func MarshalPubKey(publicKey *ecdsa.PublicKey) ([]byte, error) {

	bytePublicKey, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil { return nil, err }

	return bytePublicKey, nil

}

func PemEncPrivKey(bytePrivateKey []byte) string {
	return string(pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: bytePrivateKey},
	))
}

func PemEncPubKey(bytePublicKey []byte) string {
	return string(pem.EncodeToMemory(
		&pem.Block{Type: "EC PUBLIC KEY", Bytes: bytePublicKey},
	))
}

func StorePrivKeyToRedis(redCli *goRedis.Client, ctx context.Context, privateKey *ecdsa.PrivateKey, privateKeyId string, ttls int) error {

	bytePrivateKey, err := MarshalPrivKey(privateKey)

	if err != nil { return err }

	err = redis.SetToRedis(redCli, ctx, privateKeyId, PemEncPrivKey(bytePrivateKey), ttls)

	if err != nil { return err }

	return nil

}

func StorePubKeyToRedis(redCli *goRedis.Client, ctx context.Context, publicKey *ecdsa.PublicKey, publicKeyId string, ttls int) error {

	bytePublicKey, err := MarshalPubKey(publicKey)

	if err != nil { return err }

	err = redis.SetToRedis(redCli, ctx, publicKeyId, PemEncPubKey(bytePublicKey), ttls)

	if err != nil { return err }

	return nil

}
