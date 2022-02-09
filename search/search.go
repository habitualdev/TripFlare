package search

import (
	data "TripFlare/db"
	"TripFlare/slack"
	"TripFlare/structs"
	"bytes"
	"encoding/json"
	vt "github.com/VirusTotal/vt-go"
	"github.com/shomali11/slacker"
	bolt "go.etcd.io/bbolt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"time"
)



func SearchVirustotal(hash string) bool {
	vtClient := vt.NewClient(vtApiKey)
	file, _ := vtClient.Get(vt.URL("files/%s", hash))
	if len(file.Data) != 0 {
		return true
	}
	return false
}

func SearchVX(hash string) bool {
	data := vxApiCreds

	vxToken := structs.VxToken{}

	cli := http.Client{}
	req, _ := http.NewRequest(http.MethodPost, "https://virus.exchange/api/auth/login", bytes.NewBuffer([]byte(data)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := cli.Do(req)
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(bodyBytes, &vxToken)
	cli2 := http.Client{}
	req2, _ := http.NewRequest(http.MethodGet, "https://virus.exchange/api/file/"+hash, nil)
	req2.Header.Set("Authorization", "Bearer "+vxToken.Token)
	resp2, _ := cli2.Do(req2)
	bodyBytes2, _ := ioutil.ReadAll(resp2.Body)
	if string(bodyBytes2) == "{\"message\": \"Object not found\"}" {
		return false
	} else {
		return true
	}
}

func SearchMB(hash string) bool {

	data := url.Values{
		"query": {"get_info"},
		"hash":  {hash},
	}

	cli := http.Client{}

	req, _ := http.NewRequest(http.MethodPost, "https://mb-api.abuse.ch/api/v1/", bytes.NewBufferString(data.Encode()))

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.Header.Add("API-KEY", mbApiKey)

	resp, _ := cli.Do(req)

	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	if match, _ := regexp.Match("hash_not_found", bodyBytes); match {
		return false
	} else {
		return true
	}
}

func IterateDb(db *bolt.DB, bot *slacker.Slacker) error {

	var updatedEntries []structs.HashEntry
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("HashList"))
		if b == nil {

		}
		b.ForEach(func(k, v []byte) error {
			tempData := structs.EntryData{}
			json.Unmarshal(v, &tempData)

			tempEntry := structs.HashEntry{Hash: string(k), Data: tempData}

			if tempEntry.Data.VX || tempEntry.Data.VirusTotal || tempEntry.Data.MalwareBazaar {
				return nil
			} else {

				updatedEntry := SearchAll(tempEntry)

				updatedEntries = append(updatedEntries, updatedEntry)

				slack.SendUpdate(bot, updatedEntry.Data.User, updatedEntry)
				return nil
			}
		})

		return nil
	})
	for _, update := range updatedEntries {
		data.AddHashData(update, db)
	}
	return nil
}

func SearchAll(hashEntry structs.HashEntry) structs.HashEntry {
	tempEntry := hashEntry

	if vxApiCreds != ""{tempEntry.Data.VX = SearchVX(tempEntry.Hash)}
	if vtApiKey != ""{tempEntry.Data.VirusTotal = SearchVirustotal(tempEntry.Hash)}
	if mbApiKey != ""{tempEntry.Data.MalwareBazaar = SearchMB(tempEntry.Hash)}

	return tempEntry

}

func SearchLoop(bot *slacker.Slacker, db *bolt.DB) {
	time.Sleep(1 * time.Second)
	for true {
		IterateDb(db, bot)
		time.Sleep(2 * time.Minute)
	}
}
