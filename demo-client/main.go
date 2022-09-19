package main

import (
	"fmt"
	singlepacketauthorization "ngk_client/singlePacketAuthorization"
	"os"
)

func main() {
	SPAHandler := new(singlepacketauthorization.Singlepacketauthorization)
	fmt.Print(os.Args)
	var serverAddress string
	var secretKey string
	var signKey string
	var accessPort string

	for i, arg := range os.Args[1:] {
		if arg == "-d" {
			serverAddress = os.Args[i+2]
		}
		if arg == "--secret-key" {
			secretKey = os.Args[i+2]
		}
		if arg == "--sign-key" {
			signKey = os.Args[i+2]
		}
		if arg == "-a" {
			accessPort = os.Args[i+2]
		}
	}
	SPAHandler.Init(serverAddress, accessPort, secretKey, signKey)
}
