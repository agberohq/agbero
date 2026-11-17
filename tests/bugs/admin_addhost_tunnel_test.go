package bugs

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestADMIN_AddHostTunnelRequiresExplicitEnable executes the real
// host-builder.js. A stale backend_tunnel value must be ignored unless the
// wizard's tunnel toggle is enabled.
func TestADMIN_AddHostTunnelRequiresExplicitEnable(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	builder, err := filepath.Abs(filepath.Join(cwd, "..", "..", "internal", "operation", "admin", "js", "host-builder.js"))
	if err != nil {
		t.Fatal(err)
	}
	script := `
import { buildHostConfig } from 'file://` + filepath.ToSlash(builder) + `';
const route = (extra) => ({ path:'/', engineData: Object.assign({
  lb_strategy:'round_robin',
  backends_list: JSON.stringify([{address:'http://127.0.0.1:9000', weight:1}])
}, extra) });
const make = (extra) => buildHostConfig({ domain:'example.test', host_type:'proxy', routes:[route(extra)] });
console.log(JSON.stringify({
  none: make({}),
  disabled: make({tunnel_enabled:false, backend_tunnel:'socks5://127.0.0.1:9050'}),
  enabled: make({tunnel_enabled:true, backend_tunnel:'socks5://127.0.0.1:9050'}),
  legacy: make({backend_via:'tor'})
}));
`
	out, err := exec.Command(node, "--input-type=module", "-e", script).Output()
	if err != nil {
		t.Fatalf("node host-builder: %v", err)
	}
	var got map[string]struct {
		Routes []struct {
			Backends struct {
				Tunnel string `json:"tunnel"`
				Via    string `json:"via"`
			} `json:"backends"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["none"].Routes[0].Backends.Tunnel != "" {
		t.Fatal("host without a tunnel toggle emitted backend.tunnel")
	}
	if got["disabled"].Routes[0].Backends.Tunnel != "" {
		t.Fatal("disabled tunnel emitted backend.tunnel")
	}
	if got["enabled"].Routes[0].Backends.Tunnel != "socks5://127.0.0.1:9050" {
		t.Fatalf("enabled tunnel lost: %q", got["enabled"].Routes[0].Backends.Tunnel)
	}
	if got["legacy"].Routes[0].Backends.Via != "tor" {
		t.Fatalf("existing host tunnel lost: %q", got["legacy"].Routes[0].Backends.Via)
	}
}
