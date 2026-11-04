package firewall

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
	"go.etcd.io/bbolt"
)

var bucketName = []byte("firewall_rules")

type RuleIterator func(Rule) bool

type opType int

const (
	opAdd opType = iota
	opRemove
	opSync
)

type operation struct {
	Type opType
	Key  string
	Rule Rule
	Done chan struct{}
}

type Store struct {
	db     *bbolt.DB
	logger *ll.Logger
	wg     sync.WaitGroup
	once   sync.Once

	cache *mappo.Sharded[string, Rule]

	writeCh chan operation
	quit    chan struct{}

	// refs counts the engines sharing this store. A config reload hands the open
	// store to the replacement engine (bbolt holds an exclusive file lock, so the
	// file cannot simply be reopened) and the store must stay alive until the
	// draining engine has finished serving. NewStore starts at 1; each adopting
	// engine adds one; Close releases one and the last release closes the DB.
	refs atomic.Int32
}

func NewStore(dataDir expect.Folder, logger *ll.Logger) (*Store, error) {
	if !dataDir.IsSet() {
		return nil, def.ErrDataDirNotSet
	}
	if err := dataDir.Ensure("", true); err != nil {
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

	s := &Store{
		db:      db,
		logger:  logger,
		cache:   mappo.NewSharded[string, Rule](),
		writeCh: make(chan operation, 1000),
		quit:    make(chan struct{}),
	}
	s.refs.Store(1)

	if err := s.loadToMemory(); err != nil {
		db.Close()
		return nil, err
	}

	s.wg.Add(1)
	go s.persistLoop()

	return s, nil
}

// Retain adds a reference for an additional engine that will share this store
// (see Store.refs). Every Retain must be balanced by a Close.
func (s *Store) Retain() {
	if s == nil {
		return
	}
	s.refs.Add(1)
}

func (s *Store) loadToMemory() error {
	return s.db.View(func(tx *bbolt.Tx) error {
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
			if !r.IsExpired() {
				s.cache.Set(string(k), r)
			}
		}
		return nil
	})
}

// Close releases one reference to the store. The persist loop is stopped and the
// bolt database is closed only when the last reference is released, so a
// config-reload handover can keep the same open file alive for both the draining
// and the replacement engine.
// Safe to call multiple times per reference holder (idempotent per call) — but
// each call releases one reference, so callers must pair it with NewStore/Retain.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	if s.refs.Add(-1) > 0 {
		return nil
	}
	s.once.Do(func() { close(s.quit) })
	s.wg.Wait()
	return s.db.Close()
}

func (s *Store) Add(r Rule) error {
	s.cache.Set(r.IP, r)
	select {
	case s.writeCh <- operation{Type: opAdd, Key: r.IP, Rule: r}:
	default:
		s.logger.Warn("firewall write buffer full, persistence dropped to preserve throughput")
	}
	return nil
}

func (s *Store) Remove(ip string) error {
	s.cache.Delete(ip)
	select {
	case s.writeCh <- operation{Type: opRemove, Key: ip}:
	default:
		s.logger.Warn("firewall write buffer full, persistence dropped to preserve throughput")
	}
	return nil
}

// Sync blocks until all pending write operations are persisted to disk.
func (s *Store) Sync() error {
	done := make(chan struct{})
	select {
	case s.writeCh <- operation{Type: opSync, Done: done}:
	case <-s.quit:
		return fmt.Errorf("store closed")
	}
	<-done
	return nil
}

func (s *Store) GetBan(ip string) (*Rule, error) {
	if r, ok := s.cache.Get(ip); ok {
		return &r, nil
	}
	return nil, fmt.Errorf("not found")
}

func (s *Store) IterateActive(iter RuleIterator) error {
	s.cache.Range(func(k string, r Rule) bool {
		if r.IsExpired() {
			return true
		}
		return iter(r)
	})
	return nil
}

func (s *Store) LoadAll() ([]Rule, error) {
	var active []Rule
	s.IterateActive(func(r Rule) bool {
		active = append(active, r)
		return true
	})
	return active, nil
}

func (s *Store) Clear() error {
	s.cache.Clear()
	return s.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.DeleteBucket(bucketName); err != nil {
			if err == bbolt.ErrBucketNotFound {
				return nil
			}
			return err
		}
		_, err := tx.CreateBucket(bucketName)
		return err
	})
}

func (s *Store) PruneExpired() (int, error) {
	removed := s.cache.ClearIf(func(key string, r Rule) bool {
		return r.IsExpired()
	})

	err := s.db.Update(func(tx *bbolt.Tx) error {
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
				_ = b.Delete(k)
			}
		}
		return nil
	})

	return removed, err
}

func (s *Store) persistLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var ops []operation

	flush := func() {
		if len(ops) == 0 {
			return
		}

		var syncOps []operation

		// Always close sync operation channels regardless of transaction success/failure
		defer func() {
			for _, op := range syncOps {
				close(op.Done)
			}
		}()

		err := s.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket(bucketName)
			for _, op := range ops {
				switch op.Type {
				case opAdd:
					val, _ := json.Marshal(op.Rule)
					if err := b.Put([]byte(op.Key), val); err != nil {
						return err
					}
				case opRemove:
					if err := b.Delete([]byte(op.Key)); err != nil {
						return err
					}
				case opSync:
					syncOps = append(syncOps, op)
				}
			}
			return nil
		})

		if err != nil {
			s.logger.Fields("err", err).Error("failed to flush firewall rules to db")
		}

		ops = ops[:0]
	}

	for {
		select {
		case op := <-s.writeCh:
			ops = append(ops, op)
			if op.Type == opSync || len(ops) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.quit:
			flush()
			return
		}
	}
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
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired reports whether the ban rule has passed its expiry time.
// Rules with a zero ExpiresAt never expire.
func (r *Rule) IsExpired() bool {
	if r.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(r.ExpiresAt)
}
