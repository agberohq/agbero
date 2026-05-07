package stash

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/go-redis/redis/v8"
)

type RedisStore struct {
	client     *redis.Client
	prefix     string
	defaultTTL time.Duration
	policy     *alaye.TTLPolicy
}

func NewRedisStore(cfg *Config) (*RedisStore, error) {
	addr := "localhost:6379"
	password := ""
	db := 0
	prefix := "agbero:cache:"

	if cfg.Redis != nil {
		if cfg.Redis.Host != "" {
			port := 6379
			if cfg.Redis.Port > 0 {
				port = cfg.Redis.Port
			}
			addr = fmt.Sprintf("%s:%d", cfg.Redis.Host, port)
		}
		if cfg.Redis.Password != "" {
			password = cfg.Redis.Password
		}
		if cfg.Redis.DB >= 0 {
			db = cfg.Redis.DB
		}
		if cfg.Redis.KeyPrefix != "" {
			prefix = cfg.Redis.KeyPrefix
		}
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisStore{
		client:     client,
		prefix:     prefix,
		defaultTTL: cfg.DefaultTTL,
		policy:     cfg.Policy,
	}, nil
}

func (s *RedisStore) Get(key string) (*Entry, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := s.client.Get(ctx, s.prefix+key).Bytes()
	if err != nil {
		return nil, false
	}

	e, err := s.decode(data)
	if err != nil {
		return nil, false
	}

	return e, true
}

func (s *RedisStore) Set(key string, entry *Entry, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	entry.TTL = ttl

	data, err := s.encode(entry)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipe := s.client.Pipeline()
	pipe.Set(ctx, s.prefix+key, data, ttl)

	// Index entry under each surrogate tag for efficient PurgeByTag.
	// Tag index key: agbero:tag:<tag> → set of cache keys
	for _, tag := range entry.SurrogateTags {
		tagKey := s.tagIndexKey(tag)
		pipe.SAdd(ctx, tagKey, key)
		pipe.Expire(ctx, tagKey, ttl+time.Minute) // slightly longer than entry TTL
	}
	_, _ = pipe.Exec(ctx)
}

func (s *RedisStore) SetWithPolicy(key string, entry *Entry, policy *alaye.TTLPolicy, defaultTTL time.Duration) {
	usePolicy := policy
	if usePolicy == nil {
		usePolicy = s.policy
	}

	if usePolicy == nil || !usePolicy.IsEnabled() {
		s.Set(key, entry, defaultTTL)
		return
	}

	ttl := usePolicy.GetTTL(defaultTTL, entry.ContentType)
	// RFC 7234: cap policy TTL to upstream max-age when it is shorter and non-zero.
	if defaultTTL > 0 && ttl > defaultTTL {
		ttl = defaultTTL
	}
	if ttl <= 0 {
		return
	}
	s.Set(key, entry, ttl)
}

func (s *RedisStore) Delete(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.client.Del(ctx, s.prefix+key)
}

func (s *RedisStore) Clear() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	iter := s.client.Scan(ctx, 0, s.prefix+"*", 0).Iterator()
	for iter.Next(ctx) {
		if err := s.client.Del(ctx, iter.Val()).Err(); err != nil {
			return err
		}
	}
	return iter.Err()
}

func (s *RedisStore) Close() error {
	return s.client.Close()
}

// PurgeByTag removes all entries indexed under the given surrogate tag.
// Uses the tag index maintained in Set to avoid a full SCAN.
func (s *RedisStore) Purge(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tagKey := s.tagIndexKey(tag)
	keys, err := s.client.SMembers(ctx, tagKey).Result()
	if err != nil {
		return fmt.Errorf("stash: PurgeByTag scan tag index: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	pipe := s.client.Pipeline()
	for _, k := range keys {
		pipe.Del(ctx, s.prefix+k)
	}
	pipe.Del(ctx, tagKey)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisStore) tagIndexKey(tag string) string {
	return s.prefix + "tag:" + tag
}

func (s *RedisStore) encode(e *Entry) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(e.Body); err != nil {
		return nil, err
	}
	if err := enc.Encode(e.Headers); err != nil {
		return nil, err
	}
	if err := enc.Encode(e.Status); err != nil {
		return nil, err
	}
	if err := enc.Encode(e.CreatedAt); err != nil {
		return nil, err
	}
	if err := enc.Encode(e.TTL); err != nil {
		return nil, err
	}
	if err := enc.Encode(e.VaryHeaders); err != nil {
		return nil, err
	}
	if err := enc.Encode(e.ContentType); err != nil {
		return nil, err
	}
	if err := enc.Encode(e.SurrogateTags); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *RedisStore) decode(data []byte) (*Entry, error) {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)

	var e Entry
	if err := dec.Decode(&e.Body); err != nil {
		return nil, err
	}
	if err := dec.Decode(&e.Headers); err != nil {
		return nil, err
	}
	if err := dec.Decode(&e.Status); err != nil {
		return nil, err
	}
	if err := dec.Decode(&e.CreatedAt); err != nil {
		return nil, err
	}
	if err := dec.Decode(&e.TTL); err != nil {
		return nil, err
	}
	if err := dec.Decode(&e.VaryHeaders); err != nil {
		return nil, err
	}
	if err := dec.Decode(&e.ContentType); err != nil {
		return nil, err
	}
	if err := dec.Decode(&e.SurrogateTags); err != nil {
		return nil, err
	}

	e.StoredAt = time.Now()
	return &e, nil
}
