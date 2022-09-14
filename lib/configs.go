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
	Config_name string `mapstructure:"config_name"`
	Key         string `mapstructure:"key"`
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

func LoadClientConfig() (client_config ClientConfig, err error) {

	viper.SetConfigName("client_access")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/ngk")
	viper.AddConfigPath(".")
	err = viper.ReadInConfig()
	if err != nil {
		fmt.Println("fatal error config file: %w", err)
	}
	err = viper.Unmarshal(&client_config)
	return
}
