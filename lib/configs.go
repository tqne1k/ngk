package lib

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	LOG_PATH string = "/var/log/ngk.log"
)

type Config struct {
	Device                    string `mapstructure:"DEVICE"`
	Protocol                  string `mapstructure:"PROTOCOL"`
	Port                      string `mapstructure:"PORT"`
	Snapshot_len              int    `mapstructure:"SNAPSHOT_LEN"`
	Promiscuous               bool   `mapstructure:"PROMISCUOUS"`
	Timeout                   int    `mapstructure:"TIMEOUT"`
	Client_conf               string `mapstructure:"CLIENT_CONFIG"`
	Iptables_tablename        string `mapstructure:"IPTABLES_NAME"`
	Iptables_chain            string `mapstructure:"IPTABLES_CHAIN"`
	Rule_expires              int    `mapstructure:"RULE_EXPIRES"`
	Log_path                  string `mapstructure:"LOG_PATH"`
	Iptables_access_rule_conf string `mapstructure:"IPTABLES_ACCESS_RULE_REGEX"`
}

type ClientConfig struct {
	Name          string `mapstructure:"name"`
	SourceAddress string `mapstructure:"source_address"`
	SigningKey    string `mapstructure:"signing_key"`
	EncryptionKey string `mapstructure:"encryption_key"`
	ServiceAccess string `mapstructure:"service_access"`
}

func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}
	err = viper.Unmarshal(&config)
	return
}

func LoadClientConfig() (arrayClientConfig []ClientConfig, err error) {
	// var arrayClientConfig []ClientConfig
	viper.SetConfigName("client_access")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/ngk")
	viper.AddConfigPath(".")
	err = viper.ReadInConfig()
	if err != nil {
		fmt.Println("fatal error config file: %w", err)
	}
	err = viper.UnmarshalKey("clients", &arrayClientConfig)
	return
}

func LogInIt() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	logPath, err := os.OpenFile(LOG_PATH, os.O_WRONLY|os.O_APPEND, 0755)
	if err != nil {
		logPath, _ = os.OpenFile(LOG_PATH, os.O_WRONLY|os.O_CREATE, 0755)
	}
	log.SetOutput(logPath)
}
