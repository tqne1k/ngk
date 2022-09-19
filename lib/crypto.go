package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"

	"github.com/mergermarket/go-pkcs7"
	log "github.com/sirupsen/logrus"
)

// func encodePublicKey(publicKey *ecdsa.PublicKey) string {
// 	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
// 	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
// 	base64EncodePub := base64.StdEncoding.EncodeToString([]byte(string(pemEncodedPub)))
// 	return base64EncodePub
// }

// func encodePrivateKey(privateKey *ecdsa.PrivateKey) string {
// 	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
// 	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
// 	base64EncodePub := base64.StdEncoding.EncodeToString([]byte(string(pemEncoded)))
// 	return base64EncodePub
// }

// func decodePrivateKey(pemEncoded string) *ecdsa.PrivateKey {
// 	base6PemEncoded, _ := base64.URLEncoding.DecodeString(pemEncoded)
// 	pemEncoded = string(base6PemEncoded)
// 	block, _ := pem.Decode([]byte(pemEncoded))
// 	x509Encoded := block.Bytes
// 	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
// 	return privateKey
// }

func decodePublicKey(pemEncodedPub string) *ecdsa.PublicKey {
	base6PemEncodedPub, _ := base64.URLEncoding.DecodeString(pemEncodedPub)
	pemEncodedPub = string(base6PemEncodedPub)
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}

func DecryptAES(key []byte, encrypted string) (string, error) {
	cipherText, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error(err)
		return "", err
	}
	if len(cipherText) < aes.BlockSize {
		log.Error("cipherText too short")
		return "", err
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		log.Error("cipherText is not a multiple of the block size")
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)
	cipherText, _ = pkcs7.Unpad(cipherText, aes.BlockSize)
	return string(cipherText), nil
}
