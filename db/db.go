package db

import (
	"TripFlare/structs"
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"log"
)

func StartDB(filepath string) *bolt.DB {
	dbb, err := bolt.Open(filepath, 0666, nil)
	if err != nil {
		log.Fatalln(err)
	}
	AddHashData(structs.Placeholder, dbb)
	return dbb
}

func AddHashData(entry structs.HashEntry, dbb *bolt.DB) error {
	if err := dbb.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("HashList"))
		marshaledEntry, _ := json.Marshal(entry.Data)
		err := b.Put([]byte(entry.Hash), marshaledEntry)
		return err
	}); err != nil {
		return err
	}

	return nil
}
