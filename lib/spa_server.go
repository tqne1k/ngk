package lib

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// type spaPacketInfor struct {
// 	srcIPv4  string
// 	srcIPv6  string
// 	authData string
// }

type SPAServerHandler struct {
	srcIPv4  string
	srcIPv6  string
	authData string
}

func (SPAServerHandler) Init(device string) {
	fmt.Print("Initing SPA server handler...")
	var (
		snapshot_len int32 = 1024
		promiscuous  bool  = false
		err          error
		timeout      time.Duration = 100 * time.Millisecond
		handle       *pcap.Handle
	)
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	var filter string = "udp and port 62201"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		spaPacketInfor, err := getPacketInfo(packet)
		if err != nil {
			fmt.Println("Error: ", err)
		} else {
			fmt.Println("Auth data: ", spaPacketInfor.authData)
		}
	}

}

func getPacketInfo(packet gopacket.Packet) (SPAServerHandler, error) {
	spaPacketInfor := SPAServerHandler{}
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ip, _ := ipv4Layer.(*layers.IPv4)
		fmt.Println("IPv4: ", ip.SrcIP.String())
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
