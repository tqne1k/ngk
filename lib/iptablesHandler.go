package lib

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
)

const (
	tableName           = "filter"
	ProtFilterChainName = "port_jump"
	MacFilterChainName  = "mac_filter"
)

func contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

func createInputToPortFilter() {
	ipt, _ := iptables.New()
	chain := "INPUT"
	list, err := ipt.ListChains(tableName)
	fmt.Printf("chain list:%v", list)
	if err != nil {
		fmt.Printf("ListChains of Initial failed: %v", err)
	}
	isExists, _ := ipt.Exists(tableName, chain, "-j", "NGK_INPUT")
	if !isExists {
		ipt.NewChain("filter", "NGK_INPUT")
	}
}
