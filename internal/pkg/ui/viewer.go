package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/tree"
	"golang.org/x/term"
)

const (
	KB = 1024
	MB = 1024 * 1024
)

// Viewer renders directory contents using the ui theme.
// Two modes:
//
//	horizontal=true  — compact grid (used when dropping into a shell)
//	horizontal=false — lipgloss/tree with one level of expansion
type Viewer struct {
	u          *UI
	currentDir string
}

// NewViewer creates a Viewer with default UI settings.
func NewViewer() *Viewer {
	return &Viewer{u: New()}
}

// NewViewerWithUI creates a Viewer using an existing UI instance.
func NewViewerWithUI(u *UI) *Viewer {
	return &Viewer{u: u}
}

// Show renders directory contents.
func (v *Viewer) Show(dir string, horizontal bool) {
	v.currentDir = dir
	th := v.u.Theme()

	entries, err := os.ReadDir(dir)
	if err != nil {
		v.u.ErrorHint("error reading directory", err.Error())
		return
	}

	// Dirs first, then files, both sorted alphabetically.
	sort.Slice(entries, func(i, j int) bool {
		iIsDir := entries[i].IsDir()
		jIsDir := entries[j].IsDir()
		if iIsDir != jIsDir {
			return iIsDir
		}
		return entries[i].Name() < entries[j].Name()
	})

	// Header — workspace label, path, count.
	labelStyle := lipgloss.NewStyle().Foreground(th.Accent).Bold(true)
	pathStyle := lipgloss.NewStyle().Foreground(th.Primary)
	countStyle := lipgloss.NewStyle().Foreground(th.Faint)

	fmt.Printf("\n%s  %s  %s\n\n",
		labelStyle.Render("Agbero Workspace"),
		pathStyle.Render(dir),
		countStyle.Render(fmt.Sprintf("(%d items)", len(entries))),
	)

	if horizontal {
		v.showHorizontal(entries, th)
	} else {
		v.showVertical(entries, th)
	}
}

// showHorizontal renders entries as a multi-column grid.
// No emoji — colour and "/" suffix distinguish dirs from files.
func (v *Viewer) showHorizontal(entries []os.DirEntry, th Theme) {
	if len(entries) == 0 {
		return
	}

	dirStyle := lipgloss.NewStyle().Foreground(th.Accent).Bold(true)
	fileStyle := lipgloss.NewStyle().Foreground(th.Primary)
	keyStyle := lipgloss.NewStyle().Foreground(th.Warn)
	cfgStyle := lipgloss.NewStyle().Foreground(th.Success)

	var items []string
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		name := entry.Name()
		var rendered string
		if entry.IsDir() {
			rendered = dirStyle.Render(name + "/")
		} else {
			style := v.fileStyle(info, fileStyle, keyStyle, cfgStyle)
			rendered = style.Render(name)
		}
		items = append(items, rendered)
	}

	maxW := 0
	for _, item := range items {
		if w := lipgloss.Width(item); w > maxW {
			maxW = w
		}
	}

	colW := maxW + 4
	termW := v.terminalWidth()
	numCols := termW / colW
	if numCols < 1 {
		numCols = 1
	}

	for i := 0; i < len(items); i += numCols {
		for j := 0; j < numCols && i+j < len(items); j++ {
			fmt.Print(lipgloss.NewStyle().Width(colW).Render(items[i+j]))
		}
		fmt.Println()
	}
	fmt.Println()
}

// showVertical renders entries as a lipgloss/tree.
// Directories expand one level; files show with size annotations.
func (v *Viewer) showVertical(entries []os.DirEntry, th Theme) {
	rootStyle := lipgloss.NewStyle().Foreground(th.Accent).Bold(true)
	enumStyle := lipgloss.NewStyle().Foreground(th.Border).MarginRight(1)

	t := tree.New().
		Root(filepath.Base(v.currentDir)).
		RootStyle(rootStyle).
		Enumerator(tree.RoundedEnumerator).
		EnumeratorStyle(enumStyle)

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if entry.IsDir() {
			sub := v.buildSubTree(entry, th)
			t.Child(sub)
		} else {
			t.Child(v.fileLabel(info, th))
		}
	}

	fmt.Println(t.String())
	fmt.Println()
}

// buildSubTree builds a one-level sub-tree for a directory entry.
func (v *Viewer) buildSubTree(entry os.DirEntry, th Theme) *tree.Tree {
	dirStyle := lipgloss.NewStyle().Foreground(th.Accent).Bold(true)
	enumStyle := lipgloss.NewStyle().Foreground(th.Border).MarginRight(1)

	sub := tree.New().
		Root(dirStyle.Render(entry.Name())).
		Enumerator(tree.RoundedEnumerator).
		EnumeratorStyle(enumStyle)

	subPath := filepath.Join(v.currentDir, entry.Name())
	subEntries, err := os.ReadDir(subPath)
	if err != nil {
		return sub
	}

	sort.Slice(subEntries, func(i, j int) bool {
		return subEntries[i].Name() < subEntries[j].Name()
	})

	for _, se := range subEntries {
		seInfo, err := se.Info()
		if err != nil {
			continue
		}
		if se.IsDir() {
			// Show sub-directories as plain labels — don't recurse deeper.
			sub.Child(lipgloss.NewStyle().
				Foreground(th.Accent).
				Render(se.Name() + "/"))
		} else {
			sub.Child(v.fileLabel(seInfo, th))
		}
	}

	return sub
}

// fileLabel renders a filename with size annotation, coloured by type.
func (v *Viewer) fileLabel(info os.FileInfo, th Theme) string {
	sizeStyle := lipgloss.NewStyle().Foreground(th.Faint)
	name := info.Name()
	size := sizeStyle.Render(v.formatSize(info.Size()))

	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pem", ".key", ".cert", ".secret", ".env":
		return lipgloss.NewStyle().Foreground(th.Warn).Render(name) + "  " + size
	case ".hcl", ".yaml", ".yml", ".toml", ".json":
		return lipgloss.NewStyle().Foreground(th.Success).Render(name) + "  " + size
	case ".log":
		return lipgloss.NewStyle().Foreground(th.Secondary).Render(name) + "  " + size
	case ".db", ".sqlite":
		return lipgloss.NewStyle().Foreground(th.Secondary).Render(name) + "  " + size
	default:
		return lipgloss.NewStyle().Foreground(th.Primary).Render(name) + "  " + size
	}
}

// fileStyle returns the colour style for a file in horizontal mode.
func (v *Viewer) fileStyle(info os.FileInfo, plain, key, cfg lipgloss.Style) lipgloss.Style {
	ext := strings.ToLower(filepath.Ext(info.Name()))
	switch ext {
	case ".pem", ".key", ".cert", ".secret", ".env":
		return key
	case ".hcl", ".yaml", ".yml", ".toml", ".json":
		return cfg
	default:
		return plain
	}
}

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

func (v *Viewer) terminalWidth() int {
	fd := int(os.Stdout.Fd())
	if term.IsTerminal(fd) {
		width, _, err := term.GetSize(fd)
		if err == nil {
			return width
		}
	}
	return 80
}
