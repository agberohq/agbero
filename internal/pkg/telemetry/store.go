package telemetry

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
	"go.etcd.io/bbolt"
)

const (
	// retentionPeriod is how long we keep samples.
	retentionPeriod = 24 * time.Hour

	// CollectInterval is how often the collector takes a snapshot.
	CollectInterval = 60 * time.Second
)

var (
	bucketMeta    = []byte("meta")
	bucketSamples = []byte("samples") // sub-buckets keyed by host
)

// Store is a bbolt-backed time-series store for telemetry samples.
// All writes are async (non-blocking channel), reads are direct DB queries.
// Zero allocations on the hot path — the collector goroutine owns all writes.
type Store struct {
	db        *bbolt.DB
	writeCh   chan writeOp
	quit      chan struct{}
	closeOnce sync.Once
}

type writeOp struct {
	host   string
	sample Sample
}

// NewStore opens (or creates) the telemetry database at dataDir/telemetry.db.
func NewStore(dataDir expect.Folder) (*Store, error) {
	path := dataDir.FilePath("telemetry.db")
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("telemetry: open db: %w", err)
	}

	// Ensure top-level buckets exist.
	if err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketSamples); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketMeta)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("telemetry: init buckets: %w", err)
	}

	s := &Store{
		db:      db,
		writeCh: make(chan writeOp, 256),
		quit:    make(chan struct{}),
	}
	go s.writeLoop()
	return s, nil
}

// Record enqueues a sample for async persistence.
// Never blocks the collector goroutine.
func (s *Store) Record(host string, sample Sample) {
	select {
	case s.writeCh <- writeOp{host: host, sample: sample}:
	default:
		// write buffer full — drop rather than block
	}
}

// Query returns samples for host within the given range, down-sampled to
// the resolution defined by the QueryRange.
func (s *Store) Query(host string, qr QueryRange) ([]Sample, error) {
	cutoff := time.Now().Add(-qr.Duration).Unix()
	var out []Sample

	err := s.db.View(func(tx *bbolt.Tx) error {
		parent := tx.Bucket(bucketSamples)
		if parent == nil {
			return nil
		}
		hb := parent.Bucket([]byte(host))
		if hb == nil {
			return nil
		}

		resSec := int64(qr.Resolution.Seconds())
		var lastBucket int64

		c := hb.Cursor()
		// Seek to first key >= cutoff
		seekKey := tsKey(cutoff)
		for k, v := c.Seek(seekKey); k != nil; k, v = c.Next() {
			ts := int64(binary.BigEndian.Uint64(k))
			// Down-sample: one point per resolution bucket
			bucket := (ts / resSec) * resSec
			if bucket == lastBucket {
				continue
			}
			lastBucket = bucket

			var s Sample
			if err := json.Unmarshal(v, &s); err != nil {
				continue
			}
			out = append(out, s)
		}
		return nil
	})
	return out, err
}

// Hosts returns all host names that have recorded data.
func (s *Store) Hosts() ([]string, error) {
	var hosts []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSamples)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if v == nil { // sub-bucket
				hosts = append(hosts, string(k))
			}
			return nil
		})
	})
	return hosts, err
}

// Close flushes pending writes and closes the database.
// Safe to call more than once — subsequent calls are no-ops.
func (s *Store) Close() (err error) {
	s.closeOnce.Do(func() {
		close(s.quit)
		err = s.db.Close()
	})
	return err
}

// writeLoop drains writeCh, batching writes every 5 seconds for efficiency.
func (s *Store) writeLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var pending []writeOp

	flush := func() {
		if len(pending) == 0 {
			return
		}
		_ = s.db.Update(func(tx *bbolt.Tx) error {
			parent := tx.Bucket(bucketSamples)
			for _, op := range pending {
				hb, err := parent.CreateBucketIfNotExists([]byte(op.host))
				if err != nil {
					continue
				}
				val, err := json.Marshal(op.sample)
				if err != nil {
					continue
				}
				_ = hb.Put(tsKey(op.sample.Timestamp), val)
			}
			return nil
		})
		pending = pending[:0]
	}

	pruneOld := func() {
		cutoff := time.Now().Add(-retentionPeriod).Unix()
		_ = s.db.Update(func(tx *bbolt.Tx) error {
			parent := tx.Bucket(bucketSamples)
			if parent == nil {
				return nil
			}
			return parent.ForEach(func(k, v []byte) error {
				if v != nil {
					return nil // not a sub-bucket
				}
				hb := parent.Bucket(k)
				if hb == nil {
					return nil
				}
				c := hb.Cursor()
				for ck, _ := c.First(); ck != nil; ck, _ = c.Next() {
					ts := int64(binary.BigEndian.Uint64(ck))
					if ts >= cutoff {
						break
					}
					_ = hb.Delete(ck)
				}
				return nil
			})
		})
	}

	pruneAt := time.Now().Add(time.Hour) // prune once per hour

	for {
		select {
		case op := <-s.writeCh:
			pending = append(pending, op)
			if len(pending) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
			if time.Now().After(pruneAt) {
				pruneOld()
				pruneAt = time.Now().Add(time.Hour)
			}
		case <-s.quit:
			// drain remaining
			for {
				select {
				case op := <-s.writeCh:
					pending = append(pending, op)
				default:
					flush()
					return
				}
			}
		}
	}
}

// tsKey encodes a Unix timestamp as a big-endian uint64 key.
// Big-endian ensures bbolt's B-tree iterates in chronological order.
func tsKey(ts int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(ts))
	return b
}
