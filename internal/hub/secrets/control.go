package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/zero"
)

// ControlFile is the root-only rendezvous file written while a service is
// waiting for a manual Keeper unlock. The passphrase never appears in it.
type ControlFile struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

const controlFileName = "keeper-control.json"

// StartControl starts a loopback-only unlock endpoint for a locked process.
// The endpoint is protected by a random token stored in a 0600 file. It is
// intentionally loopback-only: use SSH/port forwarding for remote access.
func StartControl(store *keeper.Keeper, dataDir expect.Folder, logger *ll.Logger) (*Control, error) {
	if store == nil {
		return nil, fmt.Errorf("keeper: nil store")
	}
	if err := dataDir.Make(true); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		ln.Close()
		return nil, err
	}
	ct := &Control{
		store: store, ln: ln, logger: logger,
		file:  dataDir.FilePath(controlFileName),
		token: hex.EncodeToString(tok),
		done:  make(chan struct{}),
	}
	cf := ControlFile{Port: ln.Addr().(*net.TCPAddr).Port, Token: ct.token}
	data, _ := json.Marshal(cf)
	if err := os.WriteFile(ct.file, data, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	_ = os.Chmod(ct.file, 0600)
	mux := http.NewServeMux()
	mux.HandleFunc("/unlock", ct.unlock)
	mux.HandleFunc("/keeper/status", ct.auth(ct.status))
	mux.HandleFunc("/keeper/list", ct.auth(ct.list))
	mux.HandleFunc("/keeper/get", ct.auth(ct.get))
	mux.HandleFunc("/keeper/set", ct.auth(ct.set))
	mux.HandleFunc("/keeper/delete", ct.auth(ct.delete))
	ct.srv = &http.Server{Handler: mux}
	go func() {
		_ = ct.srv.Serve(ln)
	}()
	if logger != nil {
		logger.Fields("file", ct.file).Info("keeper is locked; unlock endpoint ready (run 'agbero keeper unlock')")
	}
	return ct, nil
}

type Control struct {
	store  *keeper.Keeper
	ln     net.Listener
	srv    *http.Server
	file   string
	token  string
	logger *ll.Logger
	done   chan struct{}
	once   sync.Once
}

func (c *Control) unlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.EqualFold(r.Header.Get("Authorization"), "Bearer "+c.token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Passphrase == "" {
		http.Error(w, "passphrase required", http.StatusBadRequest)
		return
	}
	pass := []byte(req.Passphrase)
	err = c.store.Unlock(pass)
	zero.Bytes(pass)
	req.Passphrase = ""
	if err != nil {
		http.Error(w, "invalid passphrase", http.StatusUnauthorized)
		return
	}
	NewResolver(c.store).Wire()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"unlocked"}`))
}

func (c *Control) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Authorization"), "Bearer "+c.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (c *Control) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"locked": c.store.IsLocked()})
}

func (c *Control) list(w http.ResponseWriter, r *http.Request) {
	keys, err := c.store.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"keys": keys})
}

func (c *Control) get(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "key required", http.StatusBadRequest)
		return
	}
	value, err := c.store.Get(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"key": key, "value": string(value)})
}

func (c *Control) set(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Key == "" {
		http.Error(w, "key and value required", http.StatusBadRequest)
		return
	}
	if err := c.store.EnsureBucket(req.Key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := c.store.Set(req.Key, []byte(req.Value)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"key": req.Key, "ref": "ss://" + req.Key})
}

func (c *Control) delete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Key == "" {
		http.Error(w, "key required", http.StatusBadRequest)
		return
	}
	if err := c.store.Delete(req.Key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"deleted": req.Key})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ControlClient talks to a running service's Keeper control endpoint.
type ControlClient struct {
	cf   *ControlFile
	http *http.Client
}

func NewControlClient(dataDir expect.Folder) (*ControlClient, error) {
	cf, err := ReadControlFile(dataDir)
	if err != nil {
		return nil, err
	}
	return &ControlClient{cf: cf, http: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}}, nil
}

func (c *ControlClient) do(method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = strings.NewReader(string(data))
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", c.cf.Port, path), r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cf.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *ControlClient) Status() (bool, error) {
	var v struct {
		Locked bool `json:"locked"`
	}
	err := c.do(http.MethodGet, "/keeper/status", nil, &v)
	return v.Locked, err
}
func (c *ControlClient) List() ([]string, error) {
	var v struct {
		Keys []string `json:"keys"`
	}
	err := c.do(http.MethodGet, "/keeper/list", nil, &v)
	return v.Keys, err
}
func (c *ControlClient) Get(key string) (string, error) {
	var v struct {
		Value string `json:"value"`
	}
	err := c.do(http.MethodGet, "/keeper/get?key="+url.QueryEscape(key), nil, &v)
	return v.Value, err
}
func (c *ControlClient) Set(key, value string) error {
	return c.do(http.MethodPost, "/keeper/set", map[string]string{"key": key, "value": value}, nil)
}
func (c *ControlClient) Delete(key string) error {
	return c.do(http.MethodPost, "/keeper/delete", map[string]string{"key": key}, nil)
}

// Wait blocks until the control endpoint has unlocked the store.
func (c *Control) Wait() {
	for c.store.IsLocked() {
		time.Sleep(50 * time.Millisecond)
	}
}

func (c *Control) Close() {
	c.once.Do(func() {
		_ = os.Remove(c.file)
		_ = c.srv.Close()
		_ = c.ln.Close()
		close(c.done)
	})
}

// ControlPath returns the rendezvous path for a data directory.
func ControlPath(dataDir expect.Folder) string {
	return dataDir.FilePath(controlFileName)
}

// ReadControlFile reads the root-only unlock rendezvous.
func ReadControlFile(dataDir expect.Folder) (*ControlFile, error) {
	data, err := os.ReadFile(ControlPath(dataDir))
	if err != nil {
		return nil, err
	}
	var cf ControlFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	if cf.Port <= 0 || cf.Token == "" {
		return nil, fmt.Errorf("invalid keeper control file")
	}
	return &cf, nil
}

// UnlockControl sends a passphrase to a waiting daemon over loopback.
func UnlockControl(dataDir expect.Folder, passphrase []byte) error {
	cf, err := ReadControlFile(dataDir)
	if err != nil {
		return fmt.Errorf("keeper control endpoint not found: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"passphrase": string(passphrase)})
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/unlock", cf.Port), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cf.Token)
	req.Header.Set("Content-Type", "application/json")
	// Never honor HTTP_PROXY/HTTPS_PROXY for a loopback passphrase request.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("unlock rejected: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
