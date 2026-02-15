package firewall

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
	"go.etcd.io/bbolt"
)

var bucketName = []byte("firewall_rules")

type Store struct {
	db     *bbolt.DB
	logger *ll.Logger
	wg     sync.WaitGroup
}

func NewStore(dataDir woos.Folder, logger *ll.Logger) (*Store, error) {
	if !dataDir.IsSet() {
		return nil, woos.ErrDataDirNotSet
	}
	if err := dataDir.Ensure(woos.Folder(""), true); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir.Path(), "firewall.db")
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open firewall db: %w", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, logger: logger}, nil
}

func (s *Store) Close() error {
	s.wg.Wait()
	return s.db.Close()
}

func (s *Store) Add(r Rule) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		val, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return b.Put([]byte(r.IP), val)
	})
}

func (s *Store) Remove(ip string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		return b.Delete([]byte(ip))
	})
}

func (s *Store) GetBan(ip string) (*Rule, error) {
	var r Rule
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		v := b.Get([]byte(ip))
		if v == nil {
			return fmt.Errorf("not found")
		}
		return json.Unmarshal(v, &r)
	})
	return &r, err
}

func (s *Store) LoadAll() ([]Rule, error) {
	var active []Rule
	var expiredKeys [][]byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var r Rule
			if err := json.Unmarshal(v, &r); err != nil {
				continue
			}
			if r.IsExpired() {
				// clone k
				kc := make([]byte, len(k))
				copy(kc, k)
				expiredKeys = append(expiredKeys, kc)
				continue
			}
			active = append(active, r)
		}
		return nil
	})
	// Async cleanup
	if len(expiredKeys) > 0 {
		s.wg.Add(1)
		go func(keys [][]byte) {
			defer s.wg.Done()
			_ = s.db.Update(func(tx *bbolt.Tx) error {
				b := tx.Bucket(bucketName)
				for _, k := range keys {
					_ = b.Delete(k)
				}
				return nil
			})
		}(expiredKeys)
	}
	return active, err
}

type BlockType uint8

const (
	BlockTypeSingle BlockType = 0
	BlockTypeCIDR   BlockType = 1
)

type Rule struct {
	IP        string    `json:"ip"`
	Type      BlockType `json:"type"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func (r *Rule) IsExpired() bool {
	if r.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(r.ExpiresAt)
}
