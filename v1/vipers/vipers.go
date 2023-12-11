package vipers

import (
	"log"

	"github.com/spf13/viper"
)

func Parse(dest string, out interface{}) {
	viper.SetConfigFile(dest)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}
	if err := viper.Unmarshal(&out); err != nil {
		log.Fatal(err)
	}
}
