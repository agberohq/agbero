package helper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/scan"
)

type Scan struct {
	p *Helper
}

func (s *Scan) Run(configPath string, jsonOut bool) {
	global, err := LoadGlobal(configPath)
	if err != nil {
		s.p.Logger.Fatal("load config: ", err)
	}
	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(s.p.Logger))
	hosts, err := hm.LoadCanonicalByDomain()
	if err != nil {
		s.p.Logger.Fatal("load hosts: ", err)
	}
	home := filepath.Dir(configPath)
	dataDir := global.Storage.DataDir.Path()
	paths := scan.Paths{
		ConfigFile:           configPath,
		Home:                 home,
		DataDir:              dataDir,
		CertsDir:             global.Storage.CertsDir.Path(),
		HostsDir:             global.Storage.HostsDir.Path(),
		LogFile:              scan.LogPath(global, dataDir),
		WorkDir:              global.Storage.WorkDir.Path(),
		KeeperPassphraseFile: global.Security.Keeper.PassphraseFile,
		KeeperDB:             filepath.Join(dataDir, "keeper.db"),
	}
	report := scan.Run(global, hosts, paths)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}

	u := ui.New()
	u.Render(func() {
		u.SectionHeader("Scan")
		u.KeyValue("Config", configPath)
		u.KeyValue("Home", home)
		u.KeyValue("Data", dataDir)
		u.KeyValue("Logs", paths.LogFile)
		u.KeyValue("Hosts", fmt.Sprint(len(hosts)))
		u.Blank()
		if len(report.Findings) == 0 {
			u.SuccessLine("No issues found")
			return
		}
		for _, f := range report.Findings {
			line := fmt.Sprintf("[%s] %s — %s", strings.ToUpper(string(f.Severity)), f.Code, f.Message)
			switch f.Severity {
			case scan.Critical, scan.High:
				u.ErrorLine(line)
			case scan.Medium:
				u.WarnLine(line)
			default:
				u.InfoLine(line)
			}
			if f.Evidence != "" {
				u.InfoLine("  evidence: " + f.Evidence)
			}
			if f.Remediation != "" {
				u.InfoLine("  fix: " + f.Remediation)
			}
		}
		u.Blank()
		counts := map[scan.Severity]int{}
		for _, f := range report.Findings {
			counts[f.Severity]++
		}
		u.KeyValue("Findings", fmt.Sprintf("critical=%d high=%d medium=%d low=%d info=%d",
			counts[scan.Critical], counts[scan.High], counts[scan.Medium], counts[scan.Low], counts[scan.Info]))
	})
}
