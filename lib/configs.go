package lib

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Device       string `mapstructure:"DEVICE"`
	Protocol     string `mapstructure:"PROTOCOL"`
	Port         string `mapstructure:"PORT"`
	Snapshot_len int    `mapstructure:"SNAPSHOT_LEN"`
	Promiscuous  bool   `mapstructure:"PROMISCUOUS"`
	Timeout      int    `mapstructure:"TIMEOUT"`
	Client_conf  string `mapstructure:"CLIENT_CONFIG"`
}

type ClientConfig struct {
	Name          string `mapstructure:"name"`
	SourceAddress string `mapstructure:"source_address"`
	SigningKey    string `mapstructure:"signing_key"`
	EncryptionKey string `mapstructure:"encryption_key"`
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
