package zulu

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

type Style struct {
	Icon  string
	Color string
}

var iconMap = map[string]Style{
	"dir":     {Icon: "📂", Color: "#61AFEF"},
	"":        {Icon: "📄", Color: "#ABB2BF"},
	".go":     {Icon: "🐹", Color: "#00ADD8"},
	".rs":     {Icon: "🦀", Color: "#DEA584"},
	".py":     {Icon: "🐍", Color: "#FFD43B"},
	".js":     {Icon: "🟨", Color: "#F1E05A"},
	".ts":     {Icon: "🔷", Color: "#3178C6"},
	".php":    {Icon: "🐘", Color: "#777BB4"},
	".java":   {Icon: "☕", Color: "#E06C75"},
	".c":      {Icon: "📜", Color: "#61AFEF"},
	".cpp":    {Icon: "📜", Color: "#61AFEF"},
	".md":     {Icon: "📝", Color: "#5C6370"},
	".txt":    {Icon: "📝", Color: "#ABB2BF"},
	".pdf":    {Icon: "📕", Color: "#E06C75"},
	".jpg":    {Icon: "🖼️", Color: "#61AFEF"},
	".png":    {Icon: "🖼️", Color: "#61AFEF"},
	".gif":    {Icon: "🖼️", Color: "#61AFEF"},
	".mp4":    {Icon: "🎥", Color: "#E5C07B"},
	".mp3":    {Icon: "🎵", Color: "#E5C07B"},
	".zip":    {Icon: "📦", Color: "#98C379"},
	".tar":    {Icon: "📦", Color: "#98C379"},
	".gz":     {Icon: "📦", Color: "#98C379"},
	".json":   {Icon: "📋", Color: "#E5C07B"},
	".yaml":   {Icon: "📋", Color: "#E5C07B"},
	".toml":   {Icon: "📋", Color: "#E5C07B"},
	".env":    {Icon: "🔑", Color: "#E06C75"},
	".sh":     {Icon: "🐚", Color: "#98C379"},
	".html":   {Icon: "🌐", Color: "#E06C75"},
	".css":    {Icon: "🎨", Color: "#61AFEF"},
	".svg":    {Icon: "🖼️", Color: "#61AFEF"},
	".exe":    {Icon: "⚙️", Color: "#ABB2BF"},
	".hcl":    {Icon: "📋", Color: "#98C379"},
	".pem":    {Icon: "🔑", Color: "#E06C75"},
	".cert":   {Icon: "🔒", Color: "#E06C75"},
	".secret": {Icon: "🔒", Color: "#E06C75"},
	".wasm":   {Icon: "🧩", Color: "#61AFEF"},
}

const (
	KB = 1024
	MB = 1024 * 1024
)

type Viewer struct{}

func NewViewer() *Viewer {
	return &Viewer{}
}

// count returns the total number of entries in the directory
// Returns zero if the directory cannot be read
func (v *Viewer) count(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(entries)
}

func (v *Viewer) Show(dir string, horizontal bool) {
	fmt.Printf("\n%s 📂 %s %s\n\n",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#61AFEF")).Render("Agbero Workspace:"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#98C379")).Render(dir),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#5C6370")).Render(fmt.Sprintf("(%d items)", v.count(dir))),
	)

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("  ⚠️  Error reading directory: %v\n", err)
		return
	}

	// Sort: directories first, then alphabetical
	sort.Slice(entries, func(i, j int) bool {
		iIsDir := entries[i].IsDir()
		jIsDir := entries[j].IsDir()
		if iIsDir != jIsDir {
			return iIsDir
		}
		return entries[i].Name() < entries[j].Name()
	})

	if horizontal {
		// ==================== HORIZONTAL GRID MODE (compact) ====================
		var items []string

		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			style := v.getIconStyle(info)
			name := entry.Name()
			if entry.IsDir() {
				name += "/"
			}

			entryStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(style.Color))
			iconR := entryStyle.Render(style.Icon)
			nameR := entryStyle.Render(name)

			// icon + name (no size/<DIR> to save space)
			item := lipgloss.JoinHorizontal(lipgloss.Left, iconR, " ", nameR)
			items = append(items, item)
		}

		if len(items) == 0 {
			return
		}

		// Find widest item (lipgloss.Width correctly counts emoji width)
		maxItemW := 0
		for _, item := range items {
			if w := lipgloss.Width(item); w > maxItemW {
				maxItemW = w
			}
		}

		colPadding := 3
		colW := maxItemW + colPadding
		termW := v.getTerminalWidth()
		numCols := termW / colW
		if numCols < 1 {
			numCols = 1
		}

		// Print grid row-by-row
		for i := 0; i < len(items); i += numCols {
			for j := 0; j < numCols && i+j < len(items); j++ {
				item := items[i+j]
				// Pad each column to exact width (handles emojis perfectly)
				padded := lipgloss.NewStyle().Width(colW).Render(item)
				fmt.Print(padded)
			}
			fmt.Println()
		}

	} else {
		// ==================== VERTICAL DETAILED MODE (your original + fixes) ====================

		// Compute max visual width of names (lipgloss.Width handles emojis correctly)
		maxNameLen := 0
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() {
				name += "/"
			}
			if w := lipgloss.Width(name); w > maxNameLen {
				maxNameLen = w
			}
		}

		dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#5C6370"))

		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			style := v.getIconStyle(info)
			name := entry.Name()
			if entry.IsDir() {
				name += "/"
			}

			entryStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(style.Color))
			iconR := entryStyle.Render(style.Icon)

			// Name column is now padded with proper visual width (fixes misalignment)
			nameR := entryStyle.Width(maxNameLen + 2).Render(name)

			var suffix string
			if entry.IsDir() {
				suffix = "<DIR>"
			} else {
				suffix = v.formatSize(info.Size())
			}
			suffixR := dimStyle.Render(suffix)

			// Build line with lipgloss → perfect alignment even with big emojis
			line := lipgloss.JoinHorizontal(
				lipgloss.Left,
				"  ",
				iconR,
				nameR,
				"  ",
				suffixR,
			)
			fmt.Println(line)
		}
	}

	fmt.Println()
}

// formatSize returns a human-readable string for the given byte size
// Uses predefined KB and MB constants to avoid magic numbers
func (v *Viewer) formatSize(size int64) string {
	switch {
	case size < KB:
		return fmt.Sprintf("%d B", size)
	case size < MB:
		return fmt.Sprintf("%.1f KB", float64(size)/KB)
	default:
		return fmt.Sprintf("%.1f MB", float64(size)/MB)
	}
}

// getIconStyle selects the emoji icon and color based on file extension
// or directory type using a predefined map with fallback
func (v *Viewer) getIconStyle(info os.FileInfo) Style {
	if info.IsDir() {
		return iconMap["dir"]
	}
	ext := strings.ToLower(filepath.Ext(info.Name()))
	if style, ok := iconMap[ext]; ok {
		return style
	}
	return iconMap[""]
}

// getTerminalWidth returns the current terminal width (or 80 as fallback).
// Requires `go get golang.org/x/term`
func (v *Viewer) getTerminalWidth() int {
	fd := int(os.Stdout.Fd())
	if term.IsTerminal(fd) {
		width, _, err := term.GetSize(fd)
		if err == nil {
			return width
		}
	}
	return 80
}
