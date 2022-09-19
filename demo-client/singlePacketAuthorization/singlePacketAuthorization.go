package singlepacketauthorization

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mergermarket/go-pkcs7"
)

type Singlepacketauthorization struct{}

func (Singlepacketauthorization) Init(serverAddress string, accessPort string, secretKey string, signKey string) {
	fmt.Println("Server: ", serverAddress)
	p := make([]byte, 1024)
	conn, _ := net.Dial("udp", serverAddress+":62201")
	timestamp := fmt.Sprint(time.Now().Unix())
	authData := fmt.Sprintf("timestamp=%s,accessPort=%s", timestamp, accessPort)

	cipherAuthData, _ := EncryptAES([]byte(secretKey), authData)
	fmt.Println(cipherAuthData)

	signPrivKey := decodePrivateKey(signKey)
	hash := sha256.Sum256([]byte(cipherAuthData))
	// ECDSA Signing
	sign, _ := ecdsa.SignASN1(rand.Reader, signPrivKey, hash[:])

	signature := base64.StdEncoding.EncodeToString(sign)
	fmt.Fprintf(conn, signature+"."+cipherAuthData)
	_, err := bufio.NewReader(conn).Read(p)

	if err != nil {
		fmt.Println("Error: ", err)
	}

	conn.Close()
}

func decodePrivateKey(pemEncoded string) *ecdsa.PrivateKey {
	base6PemEncoded, _ := base64.URLEncoding.DecodeString(pemEncoded)
	pemEncoded = string(base6PemEncoded)
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}

func EncryptAES(key []byte, unencrypted string) (string, error) {
	plainText := []byte(unencrypted)
	plainText, err := pkcs7.Pad(plainText, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf(`plainText: "%s" has error`, plainText)
	}
	if len(plainText)%aes.BlockSize != 0 {
		err := fmt.Errorf(`plainText: "%s" has the wrong block size`, plainText)
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return fmt.Sprintf("%x", cipherText), nil
}
