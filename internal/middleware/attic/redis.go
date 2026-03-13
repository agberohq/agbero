package attic

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/go-redis/redis/v8"
	"github.com/olekukonko/ll"
)

// Redis implements Redis-backed cache store
type Redis struct {
	client *redis.Client
	logger *ll.Logger
	prefix string
	ctx    context.Context
}

// NewRedis creates new Redis cache store
func NewRedis(cfg *alaye.Cache, logger *ll.Logger) (*Redis, error) {
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

	return &Redis{
		client: client,
		logger: logger,
		prefix: prefix,
		ctx:    context.Background(),
	}, nil
}

func (s *Redis) Get(key string) (*Entry, bool) {
	data, err := s.client.Get(s.ctx, s.prefix+key).Bytes()
	if err != nil {
		if err != redis.Nil && s.logger != nil {
			s.logger.Error("redis get failed", "key", key, "error", err)
		}
		return nil, false
	}

	e, err := s.decode(data)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("decode failed", "key", key, "error", err)
		}
		return nil, false
	}

	return e, true
}

func (s *Redis) Set(key string, e *Entry, ttl time.Duration) {
	if ttl <= 0 {
		return
	}

	data, err := s.encode(e)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("encode failed", "key", key, "error", err)
		}
		return
	}

	if err := s.client.Set(s.ctx, s.prefix+key, data, ttl).Err(); err != nil && s.logger != nil {
		s.logger.Error("redis set failed", "key", key, "error", err)
	}
}

func (s *Redis) Delete(key string) {
	if err := s.client.Del(s.ctx, s.prefix+key).Err(); err != nil && s.logger != nil {
		s.logger.Error("redis delete failed", "key", key, "error", err)
	}
}

func (s *Redis) Clear() error {
	iter := s.client.Scan(s.ctx, 0, s.prefix+"*", 0).Iterator()
	for iter.Next(s.ctx) {
		if err := s.client.Del(s.ctx, iter.Val()).Err(); err != nil {
			return err
		}
	}
	return iter.Err()
}

func (s *Redis) Close() error {
	return s.client.Close()
}

func (s *Redis) encode(e *Entry) ([]byte, error) {
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

	return buf.Bytes(), nil
}

func (s *Redis) decode(data []byte) (*Entry, error) {
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

	e.StoredAt = time.Now()
	return &e, nil
}
