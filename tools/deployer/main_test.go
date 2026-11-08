package main

import (
	"strings"
	"testing"
)

func TestMapTargets(t *testing.T) {
	if mapOS("Linux") != "linux" || mapOS("Darwin") != "darwin" {
		t.Fatal("mapOS")
	}
	if mapArch("x86_64") != "amd64" || mapArch("aarch64") != "arm64" {
		t.Fatal("mapArch")
	}
}

func TestSSHTarget(t *testing.T) {
	if got := sshTarget("host.example", "root"); got != "root@host.example" {
		t.Fatalf("target = %q", got)
	}
	if got := sshTarget("root@host.example", "root"); got != "root@host.example" {
		t.Fatalf("target = %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	got := shellQuote("it's a path")
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("quote = %q", got)
	}
}

func TestGitVersion(t *testing.T) {
	v, c, _, err := gitVersion()
	if err != nil || v == "" || c == "" {
		t.Fatalf("version=%q commit=%q err=%v", v, c, err)
	}
}
