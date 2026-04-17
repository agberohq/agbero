package cluster

import (
	"context"
	"fmt"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/go-redis/redis/v8"
)

// RedisSharedState implements woos.SharedState using Redis as the distributed backend.
// Provides atomic counters and token bucket rate limiting across cluster nodes.
type RedisSharedState struct {
	client *redis.Client
	prefix string
}

// NewRedisSharedState connects to Redis to provide distributed consistency.
// Exposes atomic scripts for precise limits across independent proxies.
func NewRedisSharedState(cfg *alaye.RedisState) (*RedisSharedState, error) {
	addr := fmt.Sprintf("%s:%d", def.LocalhostIPv4, def.DefaultRedisPort)
	password := ""
	db := 0
	prefix := "agbero:state:"

	if cfg != nil {
		if cfg.Host != "" {
			port := def.DefaultRedisPort
			if cfg.Port > 0 {
				port = cfg.Port
			}
			addr = fmt.Sprintf("%s:%d", cfg.Host, port)
		}
		if cfg.Password != "" {
			password = cfg.Password
		}
		if cfg.DB >= 0 {
			db = cfg.DB
		}
		if cfg.KeyPrefix != "" {
			prefix = cfg.KeyPrefix
		}
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx, cancel := context.WithTimeout(context.Background(), def.DefaultAuthTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisSharedState{
		client: client,
		prefix: prefix,
	}, nil
}

// Increment tracks hits against a key and resets when the TTL window expires.
// Atomically increases the counter and applies expiration via a Lua pipeline.
func (r *RedisSharedState) Increment(ctx context.Context, key string, window time.Duration) (int64, error) {
	fullKey := r.prefix + key

	script := `
	local current = redis.call("INCR", KEYS[1])
	if current == 1 then
		redis.call("PEXPIRE", KEYS[1], ARGV[1])
	end
	return current
	`
	res, err := r.client.Eval(ctx, script, []string{fullKey}, window.Milliseconds()).Int64()
	return res, err
}

// AllowRateLimit acts as a distributed token bucket evaluation over Redis.
// Enforces quotas and updates capacities entirely within the database safely.
func (r *RedisSharedState) AllowRateLimit(ctx context.Context, key string, limit int, window time.Duration, burst int) (bool, error) {
	fullKey := r.prefix + "rl:" + key

	rate := float64(limit) / float64(window.Milliseconds())
	if burst <= 0 {
		burst = limit
	}

	script := `
	local key = KEYS[1]
	local rate = tonumber(ARGV[1])
	local capacity = tonumber(ARGV[2])
	local now = tonumber(ARGV[3])
	local requested = 1

	local info = redis.call("HMGET", key, "tokens", "last_refresh")
	local tokens = tonumber(info[1])
	local last_refresh = tonumber(info[2])

	if not tokens then
		tokens = capacity
		last_refresh = now
	end

	local delta = math.max(0, now - last_refresh)
	local generated = delta * rate
	tokens = math.min(capacity, tokens + generated)

	if tokens >= requested then
		tokens = tokens - requested
		redis.call("HMSET", key, "tokens", tokens, "last_refresh", now)
		local ttl = math.ceil(capacity / rate)
		if ttl > 0 then
			redis.call("PEXPIRE", key, ttl)
		end
		return 1
	else
		return 0
	end
	`

	now := time.Now().UnixNano() / 1e6
	res, err := r.client.Eval(ctx, script, []string{fullKey}, rate, burst, now).Int64()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

// Close destroys the underlying Redis connection pool gracefully.
// Must be called upon system reload or shutdown.
func (r *RedisSharedState) Close() error {
	return r.client.Close()
}

// compile-time assertion that RedisSharedState satisfies woos.SharedState
var _ woos.SharedState = (*RedisSharedState)(nil)
