package firewall

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"github.com/olekukonko/ll"
	"go.etcd.io/bbolt"
)

var bucketName = []byte("firewall_rules")

type RuleIterator func(Rule) bool

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
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 5 * time.Second})
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

func (s *Store) IterateActive(iter RuleIterator) error {
	var expiredKeys [][]byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var r Rule
			if err := json.Unmarshal(v, &r); err != nil {
				continue
			}
			if r.IsExpired() {
				kc := make([]byte, len(k))
				copy(kc, k)
				expiredKeys = append(expiredKeys, kc)
				continue
			}
			if !iter(r) {
				break
			}
		}
		return nil
	})

	// Delete within same transaction scope using Update
	if len(expiredKeys) > 0 {
		err = s.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket(bucketName)
			if b == nil {
				return nil
			}
			for _, k := range expiredKeys {
				// Re-check expiration before delete (defense against race)
				v := b.Get(k)
				if v != nil {
					var r Rule
					if json.Unmarshal(v, &r) == nil && r.IsExpired() {
						_ = b.Delete(k)
					}
				}
			}
			return nil
		})
		if err != nil {
			s.logger.Fields("err", err).Error("failed to delete expired rules")
		}
	}
	return err
}

func (s *Store) LoadAll() ([]Rule, error) {
	var active []Rule
	err := s.IterateActive(func(r Rule) bool {
		active = append(active, r)
		return true
	})
	return active, err
}

func (s *Store) Clear() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		// Delete the bucket
		if err := tx.DeleteBucket(bucketName); err != nil {
			if err == bbolt.ErrBucketNotFound {
				return nil
			}
			return err
		}
		// Recreate it empty
		_, err := tx.CreateBucket(bucketName)
		return err
	})
}

func (s *Store) PruneExpired() (int, error) {
	count := 0
	var toDelete [][]byte

	// 1. Scan for expired keys (Read-Only View)
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var r Rule
			if err := json.Unmarshal(v, &r); err != nil {
				continue
			}
			if r.IsExpired() {
				// Copy key bytes because the cursor pointer is only valid inside this tx
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				toDelete = append(toDelete, keyCopy)
			}
		}
		return nil
	})

	if err != nil {
		return 0, err
	}
	if len(toDelete) == 0 {
		return 0, nil
	}

	// 2. Delete them (Write Transaction)
	err = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err == nil {
				count++
			}
		}
		return nil
	})

	return count, err
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
