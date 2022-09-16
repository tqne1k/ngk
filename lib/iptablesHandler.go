package lib

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/go-iptables/iptables"
)

func openPortAccess(sourceAddress string, serviceAccess string) {
	config, err := LoadConfig(".")
	if err != nil {
		log.Errorf("Cannot load app config! [%s]", err)
	}

	protocol := strings.Split(serviceAccess, "/")[0]
	port := strings.Split(serviceAccess, "/")[1]

	ipt, _ := iptables.New()
	chainList := strings.Split(config.Iptables_chain, ",")

	for _, chain := range chainList {
		isExists, _ := ipt.ChainExists(config.Iptables_tablename, chain)
		if !isExists {
			log.Infof("Creating %s chain", chain)
			ipt.NewChain(config.Iptables_tablename, chain)
		}
		timestamp := time.Now().Unix()
		err = ipt.Insert(config.Iptables_tablename, chain, 1, "-s", sourceAddress, "--protocol",
			protocol, "--dport", port, "-m", "comment", "--comment", "_exp_"+fmt.Sprint(timestamp), "-j", "ACCEPT")
		if err != nil {
			fmt.Println(err)
		}
		log.Infof("Created access rule to %s for %s ==> %s, rule expires at %s", chain, sourceAddress, serviceAccess, fmt.Sprint(timestamp))
	}

}

func removeExpiresRule(config Config) {
	ipt, _ := iptables.New()
	listRules, err := ipt.List(config.Iptables_tablename, config.Iptables_chain)
	if err != nil {
		fmt.Println(err)
	}

	for _, rule := range listRules {
		re, _ := regexp.Compile(config.Iptables_access_rule_conf)
		res := re.FindStringSubmatch(rule)
		if len(res) > 0 {
			time_expires := res[5]
			rule_expires_time, err := strconv.Atoi(time_expires)
			if err != nil {
				fmt.Println("Can not convert expires time")
			}
			timestamp_now := time.Now().Unix()
			if timestamp_now-int64(rule_expires_time) > 60 {
				log.Infof("Remove rule: [%s]", rule)
				err = ipt.Delete(config.Iptables_tablename, config.Iptables_chain, "-s", res[1],
					"-p", res[2], "--dport", res[4], "-m", "comment", "--comment", "_exp_"+res[5], "-j", "ACCEPT")
				if err != nil {
					log.Errorf("Can not remove rule [%s]", rule)
				}
			}
		}
	}
}
