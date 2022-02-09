package main

import (
	"TripFlare/db"
	"TripFlare/search"
	"TripFlare/slack"
	"TripFlare/structs"
	"context"
	"github.com/shomali11/slacker"
	"time"
)

func main() {
	StartBot()
	time.Sleep(100 * time.Second)
}

func StartBot() {
	boltDb := db.StartDB("tripflare.bolt")
	bot := slacker.NewClient(search.Bot_token, search.App_token)

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
				}{User: userInfo.ID, VirusTotal: false, VX: false, MalwareBazaar: false}}

				tempEntry = search.SearchAll(bot, tempEntry)

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
