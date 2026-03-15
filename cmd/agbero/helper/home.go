package helper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/installer"
)

type HomeHelper struct {
	p *Helper
}

func (h *HomeHelper) Navigate(target, action string) {
	ctx := installer.NewContext(h.p.Logger, "")

	openShell := false
	showContent := false
	editorCmd := ""

	if strings.HasPrefix(action, "@") {
		if action == "@" {
			openShell = true
		} else {
			showContent = true
			editorCmd = strings.TrimPrefix(action, "@")
		}
	} else if target == "@" {
		target = "base"
		openShell = true
	}

	var dir, filePath string
	switch strings.ToLower(target) {
	case "hosts":
		dir = ctx.Paths.HostsDir.Path()
	case "certs":
		dir = ctx.Paths.CertsDir.Path()
	case "data":
		dir = ctx.Paths.DataDir.Path()
	case "logs":
		dir = ctx.Paths.LogsDir.Path()
	case "work":
		dir = ctx.Paths.WorkDir.Path()
	case "config":
		filePath = ctx.Paths.ConfigFile
		dir = filepath.Dir(ctx.Paths.ConfigFile)
	default:
		dir = ctx.Paths.BaseDir.Path()
	}

	if showContent && filePath != "" {
		runEditor(editorCmd, filePath)
		return
	}

	if openShell {
		if err := os.Chdir(dir); err != nil {
			fmt.Printf("failed to enter directory: %v\n", err)
			return
		}
		fmt.Printf("\033[1;34mAgbero Workspace\033[0m: %s\n\n", dir)

		lsCmd := "ls"
		if runtime.GOOS == woos.Windows {
			lsCmd = "dir"
		}
		ls := exec.Command(lsCmd)
		ls.Stdout = os.Stdout
		ls.Stderr = os.Stderr
		_ = ls.Run()

		shell := os.Getenv("SHELL")
		if shell == "" {
			if runtime.GOOS == woos.Windows {
				shell = "cmd.exe"
			} else {
				shell = "/bin/sh"
			}
		}
		cmd := exec.Command(shell)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		return
	}

	if filePath != "" {
		fmt.Println(filePath)
	} else {
		fmt.Println(dir)
	}
}
