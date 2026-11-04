package setup

import (
	"os"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestReleaseWorkflowKeepsTrustInvariants(t *testing.T) {
	workflow := readRepoFile(t, "../../.github/workflows/release.yaml")

	required := []string{
		"CGO_ENABLED: '0'",
		"ref: ${{ github.event.inputs.tag || github.ref }}",
		"draft: true",
		"actions/attest-build-provenance",
		"gh release download",
		"make_latest",
		"sha256sum -c checksums.txt",
	}
	for _, want := range required {
		if !strings.Contains(workflow, want) {
			t.Errorf("release workflow is missing %q", want)
		}
	}

	if strings.Contains(workflow, "prerelease: true") {
		t.Error("release workflow still marks every release as prerelease")
	}
}

func TestMakefileHasNoLocalPublishPath(t *testing.T) {
	makefile := readRepoFile(t, "../../Makefile")

	if strings.Contains(strings.ToLower(makefile), "goreleaser") {
		t.Error("Makefile still references GoReleaser")
	}
	if !strings.Contains(makefile, "release: tag") {
		t.Error("Makefile release target is not tag-only")
	}
	if !strings.Contains(makefile, `git push $(REMOTE) "v$(RELEASE_VERSION)"`) {
		t.Error("Makefile does not push v-prefixed tags")
	}
}
