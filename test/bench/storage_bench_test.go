package bench

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/oshodi"
	bolt "go.etcd.io/bbolt"
)

type sample struct {
	Timestamp int64   `json:"ts"`
	Requests  float64 `json:"requests_sec"`
	P99       float64 `json:"p99_ms"`
	Errors    float64 `json:"error_rate"`
}

func benchSample(i int) []byte {
	b, _ := json.Marshal(sample{Timestamp: time.Now().Unix() + int64(i), Requests: float64(i), P99: 1.2, Errors: 0.1})
	return b
}

func benchKey(i int) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, uint64(i))
	return k
}

func BenchmarkBoltPut(b *testing.B) {
	dir := b.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "b.db"), 0600, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists([]byte("s")); return err }); err != nil {
		b.Fatal(err)
	}
	val := benchSample(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("s")).Put(benchKey(i), val) }); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOshodiPut(b *testing.B) {
	dir := b.TempDir()
	db, err := oshodi.Open(filepath.Join(dir, "o.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	bucket := db.Bucket("s")
	val := benchSample(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := bucket.Set(benchKey(i), val); err != nil {
			b.Fatal(err)
		}
	}
	if err := db.Flush(); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkBoltScan(b *testing.B) {
	dir := b.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "b.db"), 0600, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		bk, _ := tx.CreateBucketIfNotExists([]byte("s"))
		for i := 0; i < 10000; i++ {
			_ = bk.Put(benchKey(i), benchSample(i))
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket([]byte("s")).Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
			}
			return nil
		})
	}
}

func BenchmarkOshodiScan(b *testing.B) {
	dir := b.TempDir()
	db, err := oshodi.Open(filepath.Join(dir, "o.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	bk := db.Bucket("s")
	for i := 0; i < 10000; i++ {
		_ = bk.Set(benchKey(i), benchSample(i))
	}
	_ = db.Flush()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bk.Scan(func(k, v []byte) bool { return true })
	}
}

var _ = fmt.Sprintf
