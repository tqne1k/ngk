package lib

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
)

func encodePublicKey(publicKey *ecdsa.PublicKey) string {
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	base64EncodePub := base64.StdEncoding.EncodeToString([]byte(string(pemEncodedPub)))
	return base64EncodePub
}

func encodePrivateKey(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	base64EncodePub := base64.StdEncoding.EncodeToString([]byte(string(pemEncoded)))
	return base64EncodePub
}

func decodePrivateKey(pemEncoded string) *ecdsa.PrivateKey {
	base6PemEncoded, _ := base64.URLEncoding.DecodeString(pemEncoded)
	pemEncoded = string(base6PemEncoded)
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}

func decodePublicKey(pemEncodedPub string) *ecdsa.PublicKey {
	base6PemEncodedPub, _ := base64.URLEncoding.DecodeString(pemEncodedPub)
	pemEncodedPub = string(base6PemEncodedPub)
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}

func EncryptAES(key []byte, plaintext string) string {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(plaintext))
	c.Encrypt(out, []byte(plaintext))
	return hex.EncodeToString(out)
}

func DecryptAES(key []byte, ct string) string {
	ciphertext, _ := hex.DecodeString(ct)
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	pt := make([]byte, len(ciphertext))
	c.Decrypt(pt, ciphertext)
	s := string(pt[:])
	return s
}
