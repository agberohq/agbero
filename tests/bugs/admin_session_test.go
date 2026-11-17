package bugs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestADMIN_SessionSurvivesReload guards the boot sequence of the admin UI.
//
// The vendored oja build ends the session on ANY 401 (`api:unauthorized` →
// auth.session.refresh() → end()). auth.session.tokenSync() only reads the
// in-memory copy, which is empty after a page reload — so the UI used to send
// every request unauthenticated after F5 and log itself out within one polling
// cycle. The fix is to await auth.session.token() (which decrypts and primes the
// in-memory copy) and to answer the refresh hook with the server's /refresh.
func TestADMIN_SessionSurvivesReload(t *testing.T) {
	main := readAdminJS(t, "js/main.js")

	if strings.Contains(main, "const token = auth.session.tokenSync();") {
		t.Error("main.js restores the token with tokenSync() alone — after a reload that returns null, " +
			"every request 401s and oja ends the session. Use await auth.session.token() as the fallback.")
	}
	if !strings.Contains(main, "await auth.session.token()") {
		t.Error("main.js never awaits auth.session.token(); the session cannot be restored after a reload")
	}
	if !strings.Contains(main, "OnRefresh") {
		t.Error("main.js does not register auth.session.OnRefresh — oja's default refresh path expects a " +
			"refresh_token we never store, and ends the session when it fails")
	}

	api := readAdminJS(t, "js/api.js")
	if !strings.Contains(api, "export async function refreshToken") {
		t.Error("api.js does not export refreshToken() — POST /refresh is the only way to renew the admin JWT")
	}
}

func readAdminJS(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join(adminRoot, rel)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}
