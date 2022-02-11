package main

import (
	"TripFlare/db"
	"TripFlare/search"
	"TripFlare/slack"
	"TripFlare/structs"
	"context"
	"fmt"
	"github.com/shomali11/slacker"
	"io/ioutil"
	"os"
	"time"
)

func main() {

	if _, err := os.Stat("tripflare.yaml"); err != nil{
		fmt.Println("Config not found, creating blank config file...")
		fmt.Println("Add Details to tripflare.yaml")
		ioutil.WriteFile("tripflare.yaml",[]byte(structs.BlankTemplate),0666)
		os.Exit(0)
	}

	StartBot()
	time.Sleep(100 * time.Second)
}

func StartBot() {
	structs.NewConfig()

	boltDb := db.StartDB("tripflare.bolt")
	bot := slacker.NewClient(structs.Bot_token, structs.App_token)
	definition := &slacker.CommandDefinition{
		Description: "Add a hash to be watched",
		Example:     "AddHash <MD5/SHA256/Etc Hash>",
		Handler: func(botCtx slacker.BotContext, request slacker.Request, response slacker.ResponseWriter) {
			hash := request.Param("word")
			ev := botCtx.Event()
			userInfo, _ := bot.GetUserInfo(ev.User)
			if len(hash) == 32 || len(hash) == 64 || len(hash) == 40 {
				response.Reply("Now watching for " + hash)
				tempEntry := structs.HashEntry{Hash: hash, Data: struct {
					User          string
					VirusTotal    bool
					VX            bool
					MalwareBazaar bool
					HybridAnalysis bool
				}{User: userInfo.ID, VirusTotal: false, VX: false, MalwareBazaar: false, HybridAnalysis: false}}
				tempEntry = search.SearchAll(tempEntry)
				if tempEntry.Data.VX || tempEntry.Data.VirusTotal || tempEntry.Data.MalwareBazaar {
					slack.SendUpdate(bot, tempEntry.Data.User, tempEntry)
				}
				db.AddHashData(tempEntry, boltDb)
			} else {

				response.Reply(userInfo.Name + ": Submitted hash unknown/not supported ")
			}
		},
	}
	bot.Command("AddHash <word>", definition)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go search.SearchLoop(bot, boltDb)
	bot.Listen(ctx)
}
