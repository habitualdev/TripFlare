package structs

import (
	"github.com/jinzhu/configor"
)

var Placeholder = HashEntry{
	Hash: "PLACEHOLDER",
	Data: EntryData{
		User:          "PLACEHOLDER",
		VirusTotal:    true,
		VX:            true,
		MalwareBazaar: true,
		HybridAnalysis: true,
	},
}

type HashEntry struct {
	Hash string
	Data EntryData
}

type EntryData struct {
	User          string
	VirusTotal    bool
	VX            bool
	MalwareBazaar bool
	HybridAnalysis bool
}

type VxToken struct {
	Login        string   `json:"login"`
	Capabilities []string `json:"capabilities"`
	Groups       []string `json:"groups"`
	Token        string   `json:"token"`
}


type BlankConfig struct {
	Slack struct {
		BotToken string
		AppToken string
	}
	API struct {
		VirusTotal     string
		VX             string
		MalwareBazaar  string
		HybridAnalysis string
	}
}

var RunConfig struct {
	Slack struct {
		BotToken string
		AppToken string
	}
	API struct {
		VirusTotal     string
		VX struct {
			Username   string
			Password string
		}
		MalwareBazaar  string
		HybridAnalysis string
	}
}

var BlankTemplate = `slack:
        bot_token: 
        app_token: 
api:
        virus_total: 
        vx:
			username:
			password:
        malware_bazaar: 
        hybrid_analysis: 
`

func NewConfig()  {
	configor.Load(&RunConfig, "tripflare.yaml")

	VtApiKey = RunConfig.API.VirusTotal
	MbApiKey = RunConfig.API.MalwareBazaar
	VxApiCreds = `{"login":"`+ RunConfig.API.VX.Username + `", "password":"` + RunConfig.API.VX.Password + `"}`
	HybridApiKey = RunConfig.API.HybridAnalysis
	App_token = RunConfig.Slack.AppToken
	Bot_token = RunConfig.Slack.BotToken
}

var VtApiKey = ""
var MbApiKey = ""
var VxApiCreds = ""
var HybridApiKey = ""
var App_token = ""
var Bot_token = ""
