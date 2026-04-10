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

	data, err := s.encode(entry)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.client.Set(ctx, s.prefix+key, data, ttl)
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
	if ttl <= 0 {
		return
	}

	data, err := s.encode(entry)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.client.Set(ctx, s.prefix+key, data, ttl)
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

// encode and decode methods remain the same...
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
	if err := enc.Encode(e.VaryHeaders); err != nil {
		return nil, err
	}
	if err := enc.Encode(e.ContentType); err != nil {
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
	if err := dec.Decode(&e.VaryHeaders); err != nil {
		return nil, err
	}
	if err := dec.Decode(&e.ContentType); err != nil {
		return nil, err
	}

	e.StoredAt = time.Now()
	return &e, nil
}
