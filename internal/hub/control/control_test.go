package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerClientRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(SocketPath(dir))
	s.Handle("echo", func(ctx context.Context, in json.RawMessage) (any, error) {
		var v map[string]any
		if err := json.Unmarshal(in, &v); err != nil {
			return nil, err
		}
		return v, nil
	})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, err := os.Stat(SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %v", info.Mode().Perm())
	}
	c, err := Dial(SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var out map[string]any
	if err := c.Call(context.Background(), "echo", map[string]string{"hello": "world"}, &out); err != nil {
		t.Fatal(err)
	}
	if out["hello"] != "world" {
		t.Fatalf("out = %#v", out)
	}
}

func TestMissingServer(t *testing.T) {
	_, err := Dial(filepath.Join(t.TempDir(), "missing.sock"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestServerCloseRemovesSocket(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(SocketPath(dir))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := os.Stat(SocketPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("socket still exists: %v", err)
	}
}

func TestServerUnknownOperation(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(SocketPath(dir))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := Dial(SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Call(context.Background(), "nope", nil, nil); err == nil {
		t.Fatal("unknown operation succeeded")
	}
}

func TestClientDeadline(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(SocketPath(dir))
	s.Handle("slow", func(ctx context.Context, _ json.RawMessage) (any, error) {
		time.Sleep(200 * time.Millisecond)
		return nil, nil
	})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := Dial(SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.Call(ctx, "slow", nil, nil); err == nil {
		t.Fatal("slow call did not honor deadline")
	}
}

func TestDialRetryWaitsForServer(t *testing.T) {
	dir := t.TempDir()
	path := SocketPath(dir)
	s := NewServer(path)
	s.Handle("ping", func(context.Context, json.RawMessage) (any, error) { return "pong", nil })

	started := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond)
		close(started)
		if err := s.Start(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		<-started
		_ = s.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := DialRetry(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var out string
	if err := c.Call(ctx, "ping", nil, &out); err != nil {
		t.Fatal(err)
	}
	if out != "pong" {
		t.Fatalf("out = %q", out)
	}
}
