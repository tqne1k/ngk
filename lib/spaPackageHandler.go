package lib

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SPAServerHandler struct {
	srcIPv4  string
	srcIPv6  string
	authData string
}

func (SPAServerHandler) Init() {
	fmt.Println("Initing SPA server handler...")
	config, err := LoadConfig(".")
	if err != nil {
		fmt.Println("cannot load config:", err)
	}
	var (
		snapshot_len int32         = int32(config.Snapshot_len)
		promiscuous  bool          = config.Promiscuous
		timeout      time.Duration = time.Duration(config.Timeout) * time.Millisecond
		handle       *pcap.Handle
	)
	handle, err = pcap.OpenLive(config.Device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	var filter = flag.String("f", config.Protocol+" and dst port "+config.Port, "BPF filter for pcap")
	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		spaPacketInfor, err := getPacketInfo(packet)
		if err != nil {
			fmt.Println("Error: ", err)
		} else {
			client_config, err := LoadClientConfig()
			if err != nil {
				fmt.Println("cannot load client config:", err)
			}
			for _, config := range client_config {
				verify_flag := false
				if config.SourceAddress == "any" {
					fmt.Printf("Detect request matching [%s] configuration from [%s][%s]\n", config.SourceAddress, spaPacketInfor.srcIPv4, spaPacketInfor.srcIPv6)
					verify_flag = verify_flag || verifySignature(spaPacketInfor.authData, config.SigningKey)
					fmt.Printf("Signature is %t\n", verify_flag)
				}
				if !verify_flag && config.SourceAddress == spaPacketInfor.srcIPv4 {
					fmt.Println("Detect request matching [IPv4] configuration")
					verify_flag = verify_flag || verifySignature(spaPacketInfor.authData, config.SigningKey)
					fmt.Printf("Signature is %t\n", verify_flag)
				}
				if !verify_flag && config.SourceAddress == spaPacketInfor.srcIPv6 {
					fmt.Println("Detect request matching [IPv6] configuration")
					verify_flag = verify_flag || verifySignature(spaPacketInfor.authData, config.SigningKey)
					fmt.Printf("Signature is %t\n", verify_flag)
				}
				if verify_flag {
					if verifySPA(spaPacketInfor) {
						createRuleAccept()
					}
				}
			}
		}
	}
}

func getPacketInfo(packet gopacket.Packet) (SPAServerHandler, error) {
	spaPacketInfor := SPAServerHandler{}
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ip, _ := ipv4Layer.(*layers.IPv4)
		spaPacketInfor.srcIPv4 = ip.SrcIP.String()
	} else {
		spaPacketInfor.srcIPv4 = ""
	}
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ip, _ := ipv6Layer.(*layers.IPv6)
		spaPacketInfor.srcIPv6 = ip.SrcIP.String()
	} else {
		spaPacketInfor.srcIPv6 = ""
	}
	if spaPacketInfor.srcIPv4 == "" && spaPacketInfor.srcIPv6 == "" {
		return spaPacketInfor, errors.New("can not find ip address")
	}
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		spaPacketInfor.authData = string(applicationLayer.Payload())
	}
	return spaPacketInfor, nil
}

func verifySignature(authData string, signingKey string) bool {
	authData = "MEUCIA+aNni66DOwh6TxZqt1i3tw4ayFu9fP2/UvJqJBR9fKAiEAggE+tph4uSCG9m6XAAIMCmMCUqx+VOrQ4rTn7G58bro=.hihi"
	fmt.Println("Verifing signature...")
	signature, _ := base64.StdEncoding.DecodeString(strings.Split(authData, ".")[0])
	data := strings.Split(authData, ".")[1]
	hash := sha256.Sum256([]byte(data))
	signingPublicKey := decodePublicKey(signingKey)
	valid := ecdsa.VerifyASN1(signingPublicKey, hash[:], signature)
	return valid
}

func verifySPA(spaPacketInfor SPAServerHandler) bool {
	fmt.Println("Verifing SPA packet...")

	return true
}

func createRuleAccept() {
	createInputToPortFilter()
}
