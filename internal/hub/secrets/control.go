package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

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
	go c.Close()
}

// Wait blocks until the control endpoint has unlocked the store.
func (c *Control) Wait() { <-c.done }

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
	resp, err := http.DefaultClient.Do(req)
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
