package bugs

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
)

func TestDefaultMaxBodySizeSupportsMediaUploads(t *testing.T) {
	// A 50 MiB short video plus multipart overhead must fit the default.
	const shortVideo = 50 << 20
	if def.DefaultMaxBodySize < shortVideo {
		t.Fatalf("default max body size = %d, want at least %d", def.DefaultMaxBodySize, shortVideo)
	}
}
