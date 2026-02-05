package firewall

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
	"go.etcd.io/bbolt"
)

var bucketName = []byte("firewall_rules")

type Store struct {
	db     *bbolt.DB
	logger *ll.Logger
}

func NewStore(dataDir woos.Folder, logger *ll.Logger) (*Store, error) {
	if !dataDir.IsSet() {
		return nil, woos.ErrDataDirNotSet
	}

	if err := dataDir.Ensure(woos.Folder(""), true); err != nil {
		return nil, err
	}

	dbPath := filepath.Join(dataDir.Path(), "firewall.db")

	// Open DB with 1s timeout to prevent locking issues
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open firewall db: %w", err)
	}

	// Initialize bucket
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

// LoadAll returns all active rules. It automatically deletes expired rules from disk.
func (s *Store) LoadAll() ([]Rule, error) {
	var active []Rule
	var expiredKeys [][]byte

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var r Rule
			if err := json.Unmarshal(v, &r); err != nil {
				s.logger.Warn("corrupt firewall rule", "key", string(k))
				continue
			}

			if r.IsExpired() {
				// Copy key to delete later (cannot modify inside View)
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				expiredKeys = append(expiredKeys, keyCopy)
				continue
			}

			active = append(active, r)
		}
		return nil
	})

	// Cleanup expired rules in a batch update
	if len(expiredKeys) > 0 {
		go func() {
			_ = s.db.Update(func(tx *bbolt.Tx) error {
				b := tx.Bucket(bucketName)
				for _, k := range expiredKeys {
					_ = b.Delete(k)
				}
				return nil
			})
			s.logger.Info("cleaned up expired firewall rules", "count", len(expiredKeys))
		}()
	}

	return active, err
}
