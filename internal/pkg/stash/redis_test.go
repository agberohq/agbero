package stash

import (
	"net/http"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestRedisStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Redis tests in short mode")
	}

	cfg := &Config{
		Driver:     "redis",
		DefaultTTL: time.Minute,
		Redis: &alaye.RedisCache{
			Host:      "localhost",
			Port:      6379,
			Password:  "",
			DB:        1,
			KeyPrefix: "test:",
		},
	}

	store, err := NewStore(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer store.Close()

	store.Clear()

	t.Run("Basic Set and Get", func(t *testing.T) {
		entry := &Entry{
			Body:        []byte("test body"),
			Headers:     http.Header{"Content-Type": []string{"text/plain"}},
			Status:      http.StatusOK,
			ContentType: "text/plain",
			CreatedAt:   time.Now(),
		}

		key := "test-get"
		store.Set(key, entry, time.Minute)

		got, ok := store.Get(key)
		if !ok {
			t.Fatal("expected to get entry")
		}

		if string(got.Body) != string(entry.Body) {
			t.Errorf("expected body %q, got %q", entry.Body, got.Body)
		}
	})

	t.Run("Get Non-Existent", func(t *testing.T) {
		_, ok := store.Get("non-existent-key")
		if ok {
			t.Error("expected false for non-existent key")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		entry := &Entry{
			Body:      []byte("to delete"),
			Headers:   http.Header{},
			Status:    http.StatusOK,
			CreatedAt: time.Now(),
		}

		key := "test-delete"
		store.Set(key, entry, time.Minute)

		if _, ok := store.Get(key); !ok {
			t.Error("entry should exist before delete")
		}

		store.Delete(key)

		if _, ok := store.Get(key); ok {
			t.Error("entry should not exist after delete")
		}
	})

	t.Run("TTL Expiration", func(t *testing.T) {
		entry := &Entry{
			Body:      []byte("short lived"),
			Headers:   http.Header{},
			Status:    http.StatusOK,
			CreatedAt: time.Now(),
		}

		key := "test-ttl"
		store.Set(key, entry, 100*time.Millisecond)

		if _, ok := store.Get(key); !ok {
			t.Error("entry should exist immediately")
		}

		time.Sleep(200 * time.Millisecond)

		if _, ok := store.Get(key); ok {
			t.Error("entry should have expired")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			entry := &Entry{
				Body:      []byte("test"),
				Headers:   http.Header{},
				Status:    http.StatusOK,
				CreatedAt: time.Now(),
			}
			store.Set(string(rune(i+48)), entry, time.Minute)
		}

		store.Clear()

		for i := 0; i < 5; i++ {
			if _, ok := store.Get(string(rune(i + 48))); ok {
				t.Errorf("key %d should be cleared", i)
			}
		}
	})

	t.Run("SetWithPolicy", func(t *testing.T) {
		policy := &alaye.TTLPolicy{
			Enabled: expect.Active,
			Default: expect.Duration(30 * time.Second),
			ContentType: map[string]expect.Duration{
				"text/html": expect.Duration(5 * time.Minute),
			},
		}

		entry := &Entry{
			Body:        []byte("policy test"),
			Headers:     http.Header{},
			Status:      http.StatusOK,
			ContentType: "text/html",
			CreatedAt:   time.Now(),
		}

		key := "test-policy"
		store.SetWithPolicy(key, entry, policy, time.Minute)

		if _, ok := store.Get(key); !ok {
			t.Error("entry should exist after SetWithPolicy")
		}
	})
}

func TestRedisStoreOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Redis tests in short mode")
	}

	tests := []struct {
		name  string
		redis *alaye.RedisCache
	}{
		{
			name: "Default options",
			redis: &alaye.RedisCache{
				Host: "localhost",
				Port: 6379,
			},
		},
		{
			name: "Custom DB",
			redis: &alaye.RedisCache{
				Host: "localhost",
				Port: 6379,
				DB:   2,
			},
		},
		{
			name: "Custom key prefix",
			redis: &alaye.RedisCache{
				Host:      "localhost",
				Port:      6379,
				KeyPrefix: "custom:prefix:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Driver:     "redis",
				DefaultTTL: time.Minute,
				Redis:      tt.redis,
			}

			store, err := NewStore(cfg)
			if err != nil {
				t.Skipf("Redis not available: %v", err)
			}
			defer store.Close()

			entry := &Entry{
				Body:      []byte("test"),
				Headers:   http.Header{},
				Status:    http.StatusOK,
				CreatedAt: time.Now(),
			}

			key := "option-test"
			store.Set(key, entry, time.Second)

			if _, ok := store.Get(key); !ok {
				t.Error("failed to retrieve entry with custom options")
			}

			store.Delete(key)
		})
	}
}
