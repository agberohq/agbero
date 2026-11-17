// Package tests contains bug-confirmation tests produced by the agbero audit.
//
// # CONVENTION
//
// Every TestBUG_* function asserts the behaviour that is *correct* (and that the
// audit found to be violated). While the bug exists the test FAILS and prints a
// message starting with "BUG CONFIRMED: <summary>". After the fix lands the very
// same test must pass without modification — that is what makes it a regression
// test and not just a demo.
//
// Each test carries a "// Finding: <id> — <file:line>" comment pointing at the
// code under test so the fix can be located without re-doing the analysis.
package bugs

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"golang.org/x/crypto/bcrypt"
)

var testLogger = ll.New("bugtest").Disable()

const (
	testAdminPassword  = "correct-password"
	testKeeperPasscode = "test-passphrase"
	// testTOTPSecret is a valid base32 TOTP seed (the classic "Hello!" vector).
	testTOTPSecret = "JBSWY3DPEHPK3PXP"
	testJWTSecret  = "test-jwt-secret-very-long-string-for-security"
)

// serverOpts describes the listener topology a test needs.
type serverOpts struct {
	// admin starts the admin HTTP server (requires a seeded keeper).
	admin bool
	// totp turns on the TOTP second factor for the admin login flow.
	totp bool
	// https binds an HTTPS listener (also required to activate the
	// HTTP -> HTTPS redirect handler).
	https bool
	// redirect activates bind.redirect, which makes the plain-HTTP listener
	// serve redirectToHTTPS instead of the routing handler.
	redirect bool
	// hosts runs after the host manager is primed and before Start(), so the
	// in-memory host configs survive the initial LoadAll() inside Start().
	hosts func(t *testing.T, hm *discovery.Host)
	// global mutates the global config after the defaults above are applied.
	global func(t *testing.T, g *alaye.Global)
}

type testServer struct {
	HTTPPort  int
	HTTPSPort int
	AdminPort int
	HostsDir  string
	DataDir   string
	Global    *alaye.Global
	HM        *discovery.Host
	Keeper    *keeper.Keeper

	stop func()
}

func (ts *testServer) Close() {
	if ts != nil && ts.stop != nil {
		ts.stop()
	}
}

func (ts *testServer) httpURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", ts.HTTPPort, path)
}

func (ts *testServer) adminURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", ts.AdminPort, path)
}

// startTestServer boots a real agbero server on ephemeral loopback ports.
func startTestServer(t *testing.T, o serverOpts) *testServer {
	t.Helper()

	tmp := t.TempDir()
	hostsDir := expect.NewFolder(filepath.Join(tmp, "hosts"))
	certsDir := expect.NewFolder(filepath.Join(tmp, "certs"))
	dataDir := expect.NewFolder(filepath.Join(tmp, "data"))
	workDir := expect.NewFolder(filepath.Join(tmp, "work"))
	for _, f := range []expect.Folder{hostsDir, certsDir, dataDir, workDir} {
		if err := f.Init(expect.DirPerm); err != nil {
			t.Fatalf("mkdir %s: %v", f.Path(), err)
		}
	}

	ts := &testServer{
		HTTPPort: zulu.PortFree(),
		HostsDir: hostsDir.Path(),
		DataDir:  dataDir.Path(),
	}

	global := &alaye.Global{
		Storage: alaye.Storage{
			HostsDir: hostsDir,
			CertsDir: certsDir,
			DataDir:  dataDir,
			WorkDir:  workDir,
		},
		Bind: alaye.Bind{
			HTTP:     []string{fmt.Sprintf("127.0.0.1:%d", ts.HTTPPort)},
			Redirect: expect.Inactive,
		},
		Admin: alaye.Admin{
			Enabled:   expect.Inactive,
			Telemetry: alaye.Telemetry{Enabled: expect.Inactive},
		},
		Logging: alaye.Logging{Enabled: expect.Inactive},
		Timeouts: alaye.Timeout{
			Enabled:    expect.Active,
			Read:       expect.Duration(5 * time.Second),
			Write:      expect.Duration(5 * time.Second),
			Idle:       expect.Duration(5 * time.Second),
			ReadHeader: expect.Duration(5 * time.Second),
		},
		General: alaye.General{MaxHeaderBytes: def.DefaultMaxHeaderBytes},
		Gossip:  alaye.Gossip{Enabled: expect.Inactive},
		Security: alaye.Security{
			Enabled: expect.Active,
			Keeper: alaye.Keeper{
				Enabled:    expect.Active,
				Passphrase: expect.Value(testKeeperPasscode),
			},
		},
	}

	if o.https {
		ts.HTTPSPort = zulu.PortFree()
		global.Bind.HTTPS = []string{fmt.Sprintf("127.0.0.1:%d", ts.HTTPSPort)}
	}
	if o.redirect {
		global.Bind.Redirect = expect.Active
	}
	if o.admin {
		ts.AdminPort = zulu.PortFree()
		global.Admin.Enabled = expect.Active
		global.Admin.Address = fmt.Sprintf("127.0.0.1:%d", ts.AdminPort)
		if o.totp {
			global.Admin.TOTP = alaye.TOTP{
				Enabled:    expect.Active,
				Issuer:     "agbero-test",
				Algorithm:  "SHA1",
				Digits:     6,
				Period:     30,
				WindowSize: 1,
			}
		}
	}

	if o.global != nil {
		o.global(t, global)
	}

	var ks *keeper.Keeper
	if o.admin {
		seedKeeper(t, dataDir)
		var err error
		ks, err = secrets.Open(secrets.Config{
			DataDir:     dataDir,
			Setting:     &global.Security.Keeper,
			Logger:      testLogger,
			Interactive: false,
		})
		if err != nil {
			t.Fatalf("open keeper: %v", err)
		}
	}

	hm := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))
	// Prime `loaded` so that host configs injected below are not discarded by
	// the LoadAll() call inside Server.Start().
	if _, err := hm.LoadAll(); err != nil {
		t.Fatalf("prime host manager: %v", err)
	}
	if o.hosts != nil {
		o.hosts(t, hm)
	}

	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(10 * time.Second))
	srv := agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(testLogger),
		agbero.WithShutdownManager(shutdown),
		agbero.WithKeeper(ks),
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start("")
	}()

	waitForPort(t, ts.HTTPPort)
	if ts.HTTPSPort != 0 {
		waitForPort(t, ts.HTTPSPort)
	}
	if ts.AdminPort != 0 {
		waitForPort(t, ts.AdminPort)
	}

	ts.Global = global
	ts.HM = hm
	ts.Keeper = ks
	ts.stop = func() {
		shutdown.TriggerShutdown()
		select {
		case <-errCh:
		case <-time.After(15 * time.Second):
			t.Log("warning: server did not shut down within 15s")
		}
	}
	t.Cleanup(ts.Close)
	return ts
}

// seedKeeper prepares a keeper store with every key Server.Start() requires
// (internal PPK, admin user, admin JWT secret, admin TOTP seed).
func seedKeeper(t *testing.T, dataDir expect.Folder) {
	t.Helper()

	store, err := secrets.Open(secrets.Config{
		DataDir:     dataDir,
		Logger:      testLogger,
		Interactive: false,
		Setting: &alaye.Keeper{
			Enabled:    expect.Active,
			Logging:    expect.Inactive,
			Passphrase: expect.Value(testKeeperPasscode),
		},
	})
	if err != nil {
		t.Fatalf("open keeper for seeding: %v", err)
	}
	defer store.Close()

	for _, b := range [][2]string{
		{"vault", "admin"},
		{"vault", "key"},
		{"default", "key"},
	} {
		if err := store.CreateBucket(b[0], b[1], keeper.LevelPasswordOnly, "bug-test"); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "immutable") {
				t.Fatalf("create bucket %s:%s: %v", b[0], b[1], err)
			}
		}
	}

	p := security.NewPassword()
	hash, err := p.HashWithCost(testAdminPassword, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash admin password: %v", err)
	}
	userJSON, _ := json.Marshal(alaye.User{Username: "admin", PasswordHash: hash})
	if err := store.Set(expect.Vault().AdminUser("admin"), userJSON); err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	if err := store.Set(expect.Vault().AdminJWT("admin"), []byte(testJWTSecret)); err != nil {
		t.Fatalf("seed admin jwt: %v", err)
	}
	if err := store.Set(expect.Vault().AdminTOTP("admin"), []byte(testTOTPSecret)); err != nil {
		t.Fatalf("seed admin totp: %v", err)
	}

	_, ppkPEM, err := security.GeneratePPK()
	if err != nil {
		t.Fatalf("generate internal PPK: %v", err)
	}
	if err := store.Set(expect.Vault().Key("internal"), ppkPEM); err != nil {
		t.Fatalf("seed internal PPK: %v", err)
	}
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("port %d never became reachable", port)
}

// doRequest performs a request against addr with an explicit Host header
// (needed to exercise virtual-host routing on 127.0.0.1).
func doRequest(t *testing.T, method, addr, host, path string, headers map[string]string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(method, addr+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s%s: %v", method, addr, path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}
