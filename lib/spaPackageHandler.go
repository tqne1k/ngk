package lib

import (
	"errors"
	"flag"
	"fmt"
	"log"
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
	fmt.Print("Initing SPA server handler...")
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
			if !verifySignature(spaPacketInfor) {
				fmt.Println("Verify singnature failed")
			} else {
				client_config, err := LoadClientConfig()
				if err != nil {
					fmt.Println("cannot load client config:", err)
				}
				fmt.Println("Client conf: ", client_config)
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

func verifySignature(spaPacketInfor SPAServerHandler) bool {

	return true
}
