package lib

import (
	"fmt"
	"strings"
	"time"

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

func openPortAccess(sourceAddress string, serviceAccess string) {
	protocol := strings.Split(serviceAccess, "/")[0]
	port := strings.Split(serviceAccess, "/")[1]
	config, err := LoadConfig(".")
	if err != nil {
		fmt.Println("cannot load config:", err)
	}
	ipt, _ := iptables.New()
	chainList := strings.Split(config.Iptables_chain, ",")
	for _, chain := range chainList {
		isExists, _ := ipt.ChainExists(config.Iptables_tablename, chain)
		if !isExists {
			fmt.Printf("Creating %s chain...\n", chain)
			ipt.NewChain(config.Iptables_tablename, chain)
		}
		timestamp := time.Now().Unix()
		err = ipt.Insert(config.Iptables_tablename, chain, 1, "-s", sourceAddress, "--protocol", protocol, "--dport", port, "-m", "comment", "--comment", "exp_"+fmt.Sprint(timestamp), "-j", "ACCEPT")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("Created access rule to %s for %s ==> %s, rule expires at %s\n", chain, sourceAddress, serviceAccess, fmt.Sprint(timestamp))
	}

}
