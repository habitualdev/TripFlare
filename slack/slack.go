package slack

import (
	"TripFlare/structs"
	"github.com/shomali11/slacker"
	"github.com/slack-go/slack"
)

func SendUpdate(bot *slacker.Slacker, userID string, entry structs.HashEntry) {
	if entry.Data.VX {
		bot.Client().PostMessage(userID, slack.MsgOptionText(entry.Hash+" found on VX", false))
	}
	if entry.Data.VirusTotal {
		bot.Client().PostMessage(userID, slack.MsgOptionText(entry.Hash+" found on VT", false))
	}
	if entry.Data.MalwareBazaar {
		bot.Client().PostMessage(userID, slack.MsgOptionText(entry.Hash+" found on MalwareBazaar", false))
	}
	if entry.Data.HybridAnalysis{
		bot.Client().PostMessage(userID, slack.MsgOptionText(entry.Hash+" found on HybridAnalysis", false))
	}
}
