package web

import (
	_ "embed"
	"html/template"
	"mime"
	"regexp"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/klauspost/compress/gzip"
	"github.com/olekukonko/mappo"
)

const (
	baseDecimalFormat = 10
	hexDecimalFormat  = 16
)

var (
	mimeCache sync.Map
)

//go:embed html/dir.html
var webDirHTML string

//go:embed html/md.html
var mdPageHTML string

//go:embed html/md_browse.html
var mdBrowseHTML string

var (
	dirTmpl      = template.Must(template.New("dir").Parse(webDirHTML))
	mdPageTmpl   = template.Must(template.New("md").Parse(mdPageHTML))
	mdBrowseTmpl = template.Must(template.New("md-browse").Parse(mdBrowseHTML))

	gzExistsCache = mappo.NewCache(mappo.CacheOptions{
		MaximumSize: def.CacheMax,
	})

	dynamicGzCache = mappo.NewCache(mappo.CacheOptions{MaximumSize: 256})

	fingerprintRe = regexp.MustCompile(`(?i)(?:[._-])[a-f0-9]{8,}(?:[._-])`)

	gzWriterPool = sync.Pool{
		New: func() any {
			w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
			return w
		},
	}
)

const (
	gzCacheTTL            = 60 * time.Second
	phpTimeout            = 30 * time.Second
	dynamicGzMinSize      = def.WebDynamicGzMinBytes
	dynamicGzMaxCacheSize = 512 * def.WebDynamicGzMinBytes
	dynamicGzTTL          = 60 * time.Second
)

var compressibleMIME = []string{
	"text/",
	"application/javascript",
	"application/json",
	"application/xml",
	"application/xhtml+xml",
	"application/wasm",
	"image/svg+xml",
}

var markdownExts = map[string]bool{
	".md":       true,
	".markdown": true,
	".mdown":    true,
	".mkd":      true,
}

// dangerousPHPHeaders lists headers that must never reach PHP-FPM because
// they override critical CGI/FastCGI variables.
var dangerousPHPHeaders = map[string]bool{
	"x-forwarded-host":     true,
	"x-forwarded-proto":    true,
	"x-forwarded-for":      true,
	"x-real-ip":            true,
	"x-forwarded-server":   true,
	"x-forwarded-port":     true,
	"script_filename":      true,
	"document_root":        true,
	"script_name":          true,
	"request_uri":          true,
	"query_string":         true,
	"request_method":       true,
	"server_protocol":      true,
	"gateway_interface":    true,
	"redirect_status":      true,
	"http_proxy":           true,
	"http_host":            true,
	"content_length":       true,
	"content_type":         true,
	"php_auth_user":        true,
	"php_auth_pw":          true,
	"auth_type":            true,
	"remote_addr":          true,
	"remote_port":          true,
	"server_addr":          true,
	"server_name":          true,
	"server_port":          true,
	"server_software":      true,
	"path_translated":      true,
	"path_info":            true,
	"orig_path_info":       true,
	"orig_script_name":     true,
	"orig_script_filename": true,
}

type dirItem struct {
	Name    string
	IsDir   bool
	Size    string
	ModTime string
	URL     string
	Ext     string
	MIME    string
}

type crumb struct {
	Name string
	Href string
}

type dynamicGzEntry struct {
	data    []byte
	modTime time.Time
	size    int64
}

type chromaPreWrapper struct{}

func (chromaPreWrapper) Start(code bool, _ string) string {
	if code {
		return `<pre class="chroma"><code>`
	}
	return `<pre class="chroma">`
}

func (chromaPreWrapper) End(code bool) string {
	if code {
		return `</code></pre>`
	}
	return `</pre>`
}

func init() {
	types := map[string]string{
		// Text / markup
		".html": "text/html; charset=utf-8",
		".css":  "text/css; charset=utf-8",
		".js":   "application/javascript; charset=utf-8",
		".mjs":  "text/javascript; charset=utf-8",
		".json": "application/json; charset=utf-8",
		".xml":  "text/xml; charset=utf-8",
		".txt":  "text/plain; charset=utf-8",
		".csv":  "text/csv; charset=utf-8",
		".md":   "text/markdown",
		// Images
		".svg":  "image/svg+xml",
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".gif":  "image/gif",
		".webp": "image/webp",
		".avif": "image/avif",
		".ico":  "image/x-icon",
		// Fonts
		".woff":  "font/woff",
		".woff2": "font/woff2",
		// Application
		".wasm":        "application/wasm",
		".pdf":         "application/pdf",
		".zip":         "application/zip",
		".webmanifest": "application/manifest+json",
		// Video — CDN large-file support
		".mp4":  "video/mp4",
		".webm": "video/webm",
		".ogg":  "video/ogg",
		".avi":  "video/x-msvideo",
		".mov":  "video/quicktime",
		".mkv":  "video/x-matroska",
		// Audio — CDN large-file support
		".mp3":  "audio/mpeg",
		".flac": "audio/flac",
		".aac":  "audio/aac",
		".wav":  "audio/wav",
		".opus": "audio/ogg",
	}

	for ext, mimeType := range types {
		_ = mime.AddExtensionType(ext, mimeType)
	}
}
