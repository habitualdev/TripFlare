package structs

var Placeholder = HashEntry{
	Hash: "PLACEHOLDER",
	Data: EntryData{
		User:          "PLACEHOLDER",
		VirusTotal:    true,
		VX:            true,
		MalwareBazaar: true,
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
}

type VxToken struct {
	Login        string   `json:"login"`
	Capabilities []string `json:"capabilities"`
	Groups       []string `json:"groups"`
	Token        string   `json:"token"`
}
