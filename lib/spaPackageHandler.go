package lib

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

type SPAServerHandler struct {
	srcIPv4  string
	srcIPv6  string
	authData string
}

func (SPAServerHandler) Init() {
	LogInIt()

	log.Info("Initing SPA server handler...")

	config, err := LoadConfig(".")
	if err != nil {
		log.Errorf("Cannot load app config! [%s]", err)
	}

	log.Info("Running auto remove expires rule service...")
	go func() {
		for {
			removeExpiresRule(config)
			time.Sleep(200 * time.Millisecond)
		}
	}()

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
			log.Errorf("Can not get SPA packet info! [%s]", err)
		} else {
			client_config, err := LoadClientConfig()
			if err != nil {
				log.Errorf("Cannot load client config! [%s]", err)
			}
			for _, config := range client_config {
				verify_flag := false
				if config.SourceAddress == "any" {
					log.Infof("Detect request matching [ANY] configuration from [%s %s].", spaPacketInfor.srcIPv4, spaPacketInfor.srcIPv6)
					verify_flag = verify_flag || verifySignature(spaPacketInfor.authData, config.SigningKey)
					log.Infof("Verify signature from %s / %s is %t.", spaPacketInfor.srcIPv4, spaPacketInfor.srcIPv6, verify_flag)
					if verify_flag {
						verifySPAResult, statusOK := verifySPA(config.ServiceAccess, spaPacketInfor, config.EncryptionKey)
						if statusOK {
							if spaPacketInfor.srcIPv4 != "" {
								openPortAccess(spaPacketInfor.srcIPv4, verifySPAResult)
							}
							if spaPacketInfor.srcIPv6 != "" {
								openPortAccess(spaPacketInfor.srcIPv6, verifySPAResult)
							}
						}
					}
				}
				if !verify_flag && config.SourceAddress == spaPacketInfor.srcIPv4 {
					log.Infof("Detect request matching %s configuration from %s.", config.Name, spaPacketInfor.srcIPv4)
					verify_flag = verify_flag || verifySignature(spaPacketInfor.authData, config.SigningKey)
					log.Infof("Verify signature from %s is %t.", spaPacketInfor.srcIPv4, verify_flag)
					if verify_flag {
						verifySPAResult, statusOK := verifySPA(config.ServiceAccess, spaPacketInfor, config.EncryptionKey)
						if statusOK {
							openPortAccess(spaPacketInfor.srcIPv4, verifySPAResult)
						}
					}
				}
				if !verify_flag && config.SourceAddress == spaPacketInfor.srcIPv6 {
					log.Infof("Detect request matching %s configuration from %s.", config.Name, spaPacketInfor.srcIPv6)
					verify_flag = verify_flag || verifySignature(spaPacketInfor.authData, config.SigningKey)
					log.Infof("Verify signature from %s is %t.", spaPacketInfor.srcIPv6, verify_flag)
					if verify_flag {
						verifySPAResult, statusOK := verifySPA(config.ServiceAccess, spaPacketInfor, config.EncryptionKey)
						if statusOK {
							openPortAccess(spaPacketInfor.srcIPv6, verifySPAResult)
						}
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
	fmt.Println(authData)
	signature, _ := base64.StdEncoding.DecodeString(strings.Split(authData, ".")[0])
	secretMessage := strings.Split(authData, ".")

	if len(secretMessage) != 2 {
		fmt.Println("LEN: ", len(secretMessage))
		return false
	}
	hash := sha256.Sum256([]byte(secretMessage[1]))
	signingPublicKey := decodePublicKey(signingKey)
	valid := ecdsa.VerifyASN1(signingPublicKey, hash[:], signature)
	return valid
}

func verifySPA(serviceAccess string, spaPacketInfor SPAServerHandler, encryptionKey string) (string, bool) {
	log.Infof("Verifing SPA packet data from %s %s.", spaPacketInfor.srcIPv4, spaPacketInfor.srcIPv6)
	secretMessage := strings.Split(spaPacketInfor.authData, ".")
	if len(secretMessage) != 2 {
		return "", false
	}
	packetAuthData, err := DecryptAES([]byte(encryptionKey), secretMessage[1])
	if err != nil {
		log.Error(err)
		return "", false
	}
	log.Infof("Auth data: [%s]", packetAuthData)
	arrayRequestServiceAccess := strings.Split(packetAuthData, ",")
	for _, service := range arrayRequestServiceAccess {
		if strings.Contains(service, "accessPort") {
			serviceAccessRequest := strings.Split(service, "=")
			if len(serviceAccessRequest) != 2 {
				return "", false
			}
			for _, serviceAccessMember := range strings.Split(serviceAccess, ",") {
				if serviceAccessMember == serviceAccessRequest[1] {
					return serviceAccessRequest[1], true
				}
			}
		}
	}
	log.Warn("Invalid request to service!")
	return "", false
}
