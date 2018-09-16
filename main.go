package main

import (
	"log"

	"github.com/spf13/cast"

	"github.com/spf13/viper"

	auth0sdk "github.com/apibillme/auth0-sdk"
)

func main() {

	viper.SetConfigName("account")
	viper.AddConfigPath("./conf")
	err := viper.ReadInConfig()
	if err != nil {
		log.Panic(err)
	}

	auth0Domain := cast.ToString(viper.Get("auth0_domain"))
	clientID := cast.ToString(viper.Get("auth0_client_id"))
	clientSecret := cast.ToString(viper.Get("auth0_client_secret"))

	err = auth0sdk.New(auth0Domain, clientID, clientSecret)
	if err != nil {
		log.Panic(err)
	}
	clients, err := auth0sdk.GetClients("")
	if err != nil {
		log.Panic(err)
	}
	for _, client := range clients.Array() {
		name := client.Get("name").String()
		log.Println(name)
	}
}
