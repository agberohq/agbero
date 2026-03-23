package ui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/compat"
	"charm.land/lipgloss/v2/list"
	"charm.land/lipgloss/v2/table"
	"charm.land/lipgloss/v2/tree"
)

// ─────────────────────────────────────────────
//  Icon Set
// ─────────────────────────────────────────────

type IconSet struct {
	Success         string
	Warning         string
	Error           string
	Info            string
	Arrow           string
	Bullet          string
	Checkbox        string
	CheckboxChecked string
	Folder          string
	File            string
	Key             string
	Lock            string
	Dot             string
	Dash            string
	Pipe            string
}

var DefaultIconSet = IconSet{
	Success:         "✓",
	Warning:         "⚠",
	Error:           "✗",
	Info:            "ℹ",
	Arrow:           "→",
	Bullet:          "•",
	Checkbox:        "☐",
	CheckboxChecked: "☒",
	Folder:          "📁",
	File:            "📄",
	Key:             "🔑",
	Lock:            "🔒",
	Dot:             "●",
	Dash:            "─",
	Pipe:            "│",
}

// ─────────────────────────────────────────────
//  Theme
// ─────────────────────────────────────────────

// Theme uses compat.AdaptiveColor for automatic light/dark detection
type Theme struct {
	Primary   compat.AdaptiveColor
	Secondary compat.AdaptiveColor
	Faint     compat.AdaptiveColor
	Accent    compat.AdaptiveColor
	Success   compat.AdaptiveColor
	Warn      compat.AdaptiveColor
	Danger    compat.AdaptiveColor
	Value     compat.AdaptiveColor
	Border    compat.AdaptiveColor
}

var DefaultTheme = Theme{
	Primary:   compat.AdaptiveColor{Dark: lipgloss.Color("#E2E0D9"), Light: lipgloss.Color("#2C2C2A")},
	Secondary: compat.AdaptiveColor{Dark: lipgloss.Color("#9B9A94"), Light: lipgloss.Color("#5F5E5A")},
	Faint:     compat.AdaptiveColor{Dark: lipgloss.Color("#4A4A46"), Light: lipgloss.Color("#C0BEB8")},
	Accent:    compat.AdaptiveColor{Dark: lipgloss.Color("#7CAFC4"), Light: lipgloss.Color("#2B6CB0")},
	Success:   compat.AdaptiveColor{Dark: lipgloss.Color("#7CB98A"), Light: lipgloss.Color("#276749")},
	Warn:      compat.AdaptiveColor{Dark: lipgloss.Color("#C9A95C"), Light: lipgloss.Color("#975A16")},
	Danger:    compat.AdaptiveColor{Dark: lipgloss.Color("#C07070"), Light: lipgloss.Color("#9B2C2C")},
	Value:     compat.AdaptiveColor{Dark: lipgloss.Color("#D4D2CB"), Light: lipgloss.Color("#1A1A18")},
	Border:    compat.AdaptiveColor{Dark: lipgloss.Color("#3A3A36"), Light: lipgloss.Color("#D1CFC8")},
}

// ─────────────────────────────────────────────
//  UI
// ─────────────────────────────────────────────

type UI struct {
	w                  io.Writer
	theme              Theme
	icons              IconSet
	indent             int
	buf                strings.Builder
	supportsHyperlinks bool
}

type Option func(*UI)

func WithWriter(w io.Writer) Option { return func(u *UI) { u.w = w } }
func WithTheme(t Theme) Option      { return func(u *UI) { u.theme = t } }
func WithIcons(i IconSet) Option    { return func(u *UI) { u.icons = i } }
func WithIndent(n int) Option       { return func(u *UI) { u.indent = n } }

func New(opts ...Option) *UI {
	u := &UI{
		w:      os.Stdout,
		theme:  DefaultTheme,
		icons:  DefaultIconSet,
		indent: 3,
	}
	for _, o := range opts {
		o(u)
	}
	tp := os.Getenv("TERM_PROGRAM")
	u.supportsHyperlinks = tp == "iTerm.app" || tp == "WezTerm" ||
		tp == "vscode" || tp == "ghostty" || tp == "kitty" ||
		os.Getenv("WT_SESSION") != "" || os.Getenv("HYPERLINK") != ""
	return u
}

// ─────────────────────────────────────────────
//  Internal helpers
// ─────────────────────────────────────────────

func (u *UI) s(c compat.AdaptiveColor) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(c)
}

func (u *UI) padStyle() lipgloss.Style {
	return lipgloss.NewStyle().PaddingLeft(u.indent)
}

func (u *UI) line(s string)     { u.buf.WriteString(s + "\n") }
func (u *UI) indented(s string) { u.line(u.padStyle().Render(s)) }
func (u *UI) blank()            { u.line("") }

func (u *UI) Flush() {
	lipgloss.Fprint(u.w, u.buf.String())
	u.buf.Reset()
}

func (u *UI) String() string { return u.buf.String() }
func (u *UI) Reset()         { u.buf.Reset() }

// ─────────────────────────────────────────────
//  Hyperlink (OSC 8)
// ─────────────────────────────────────────────

// Link creates an OSC 8 hyperlink. Falls back to plain text if unsupported.
func (u *UI) Link(text, url string) string {
	if !u.supportsHyperlinks {
		return text
	}
	return lipgloss.NewStyle().Hyperlink(url).Render(text)
}

// LinkInline creates a styled hyperlink with accent color and underline.
func (u *UI) LinkInline(text, url string) string {
	if !u.supportsHyperlinks {
		return u.s(u.theme.Accent).Underline(true).Render(text)
	}
	return u.s(u.theme.Accent).Underline(true).Hyperlink(url).Render(text)
}

// FileLink creates a clickable file/directory link using file:// protocol.
func (u *UI) FileLink(path string, isDir bool) string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	// Convert to file:// URL (handle Windows paths)
	url := "file://" + filepath.ToSlash(absPath)

	style := u.s(u.theme.Accent)
	if isDir {
		style = style.Bold(true)
	}

	if !u.supportsHyperlinks {
		return style.Render(path)
	}
	return style.Hyperlink(url).Render(path)
}

// ─────────────────────────────────────────────
//  Welcome
// ─────────────────────────────────────────────

func (u *UI) Welcome(name, description, version, date, banner string) {
	if banner != "" {
		u.line(u.s(u.theme.Accent).Bold(true).Render(banner))
	}
	u.indented(
		u.s(u.theme.Primary).Bold(true).Render(name) +
			"  " + u.s(u.theme.Secondary).Render("— "+description),
	)
	u.indented(u.s(u.theme.Faint).Render(version + "  ·  " + date))
	u.blank()
	u.Flush()
}

// ─────────────────────────────────────────────
//  Section header
// ─────────────────────────────────────────────

func (u *UI) SectionHeader(label string) {
	bar := lipgloss.NewStyle().
		Foreground(u.theme.Accent).
		Bold(true).
		Render("▎")
	text := u.s(u.theme.Secondary).
		Bold(true).
		Render(strings.ToUpper(label))
	u.blank()
	u.indented(bar + " " + text)
	u.blank()
	u.Flush()
}

// ─────────────────────────────────────────────
//  Key-value block
// ─────────────────────────────────────────────

type KV struct {
	Label string
	Value string
}

func (u *UI) KeyValueBlock(title string, pairs []KV) {
	if len(pairs) == 0 {
		return
	}
	maxLen := 0
	for _, kv := range pairs {
		if n := len([]rune(kv.Label)); n > maxLen {
			maxLen = n
		}
	}
	if title != "" {
		u.blank()
		u.indented(u.s(u.theme.Primary).Bold(true).Render(title))
	}
	sep := u.s(u.theme.Faint).Render(u.icons.Pipe)
	for _, kv := range pairs {
		runes := []rune(kv.Label)
		padded := string(runes) + strings.Repeat(" ", maxLen-len(runes))
		u.indented(
			u.s(u.theme.Secondary).Render(padded) +
				"  " + sep + "  " +
				u.s(u.theme.Value).Render(kv.Value),
		)
	}
	u.blank()
	u.Flush()
}

func (u *UI) KeyValue(label, value string) {
	u.KeyValueBlock("", []KV{{Label: label, Value: value}})
}

func (u *UI) KeyValueLink(label, text, url string) {
	u.KeyValue(label, u.LinkInline(text, url))
}

// KeyValueFile shows a clickable file path.
func (u *UI) KeyValueFile(label, path string, isDir bool) {
	u.KeyValue(label, u.FileLink(path, isDir))
}

// ─────────────────────────────────────────────
//  Secret box
// ─────────────────────────────────────────────

func (u *UI) SecretBox(label, value string) {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderTopForeground(u.theme.Accent).
		BorderLeftForeground(u.theme.Border).
		BorderRightForeground(u.theme.Border).
		BorderBottomForeground(u.theme.Border).
		PaddingLeft(1).
		PaddingRight(1)

	content := u.s(u.theme.Accent).Bold(true).Render(u.icons.Key+" "+label) +
		"\n" +
		u.s(u.theme.Value).Render(value)

	u.blank()
	u.indented(box.Render(content))
	u.blank()
	u.Flush()
}

// ─────────────────────────────────────────────
//  Status badge
// ─────────────────────────────────────────────

func (u *UI) StatusBadge(status string) {
	lower := strings.ToLower(strings.TrimSpace(status))
	var dotStyle, textStyle lipgloss.Style
	switch lower {
	case "running", "active", "ok":
		dotStyle, textStyle = u.s(u.theme.Success), u.s(u.theme.Success)
	case "stopped", "inactive", "disabled":
		dotStyle, textStyle = u.s(u.theme.Secondary), u.s(u.theme.Secondary)
	case "unknown", "pending", "starting":
		dotStyle, textStyle = u.s(u.theme.Warn), u.s(u.theme.Warn)
	case "error", "failed", "critical":
		dotStyle, textStyle = u.s(u.theme.Danger), u.s(u.theme.Danger)
	default:
		dotStyle, textStyle = u.s(u.theme.Secondary), u.s(u.theme.Primary)
	}
	u.blank()
	u.indented(dotStyle.Render(u.icons.Dot) + "  " + textStyle.Render(lower))
	u.blank()
	u.Flush()
}

func (u *UI) ServiceStatus(status, pid, configPath string) {
	u.SectionHeader("Service status")
	u.StatusBadge(status)
	if pid != "" {
		u.KeyValue("Process ID", pid)
	}
	if configPath != "" {
		u.KeyValueFile("Config file", configPath, false)
	}
}

// ─────────────────────────────────────────────
//  Table
// ─────────────────────────────────────────────

func (u *UI) Table(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(u.theme.Border)).
		StyleFunc(func(row, _ int) lipgloss.Style {
			if row == table.HeaderRow {
				return lipgloss.NewStyle().Foreground(u.theme.Accent).Bold(true)
			}
			return lipgloss.NewStyle().Foreground(u.theme.Primary)
		}).
		Headers(headers...).
		Rows(rows...)

	u.blank()
	u.indented(t.Render())
	u.blank()
	u.Flush()
}

type LinkCell struct {
	Text string
	URL  string
}

func (u *UI) TableWithLinks(headers []string, rows [][]interface{}) {
	if len(headers) == 0 {
		return
	}
	strRows := make([][]string, len(rows))
	for i, row := range rows {
		strRows[i] = make([]string, len(row))
		for j, cell := range row {
			switch v := cell.(type) {
			case LinkCell:
				strRows[i][j] = u.LinkInline(v.Text, v.URL)
			case string:
				strRows[i][j] = v
			default:
				strRows[i][j] = fmt.Sprintf("%v", v)
			}
		}
	}
	u.Table(headers, strRows)
}

// ─────────────────────────────────────────────
//  Help screen
// ─────────────────────────────────────────────

type HelpCmd struct {
	Cmd  string
	Desc string
	URL  string
}

type HelpSection struct {
	Title    string
	Commands []HelpCmd
}

func (u *UI) HelpScreen(sections []HelpSection) {
	maxCmd := 0
	for _, sec := range sections {
		for _, cmd := range sec.Commands {
			if n := len([]rune(cmd.Cmd)); n > maxCmd {
				maxCmd = n
			}
		}
	}

	sudoStyle := u.s(u.theme.Faint)
	binStyle := u.s(u.theme.Faint)
	subStyle := u.s(u.theme.Accent)
	actStyle := u.s(u.theme.Primary).Bold(true)
	flagStyle := u.s(u.theme.Warn)
	descStyle := u.s(u.theme.Secondary)
	sepStyle := u.s(u.theme.Faint)

	sectionBar := u.s(u.theme.Accent).Bold(true).Render("▎")
	sectionText := func(t string) string {
		return u.s(u.theme.Primary).Bold(true).Render(strings.ToUpper(t))
	}

	colourCmd := func(cmd string) string {
		words := strings.Fields(cmd)
		if len(words) == 0 {
			return cmd
		}
		out := make([]string, len(words))

		binIdx := 0
		if words[0] == "sudo" {
			out[0] = sudoStyle.Render(words[0])
			binIdx = 1
		}

		for i, w := range words {
			if i < binIdx {
				continue
			}
			switch i - binIdx {
			case 0:
				out[i] = binStyle.Render(w)
			case 1:
				out[i] = subStyle.Render(w)
			default:
				if strings.HasPrefix(w, "-") || w == "." || w == "@" || w == ":" {
					out[i] = flagStyle.Render(w)
				} else {
					out[i] = actStyle.Render(w)
				}
			}
		}
		return strings.Join(out, " ")
	}

	u.blank()

	for _, sec := range sections {
		u.indented(sectionBar + " " + sectionText(sec.Title))
		u.blank()

		for _, cmd := range sec.Commands {
			runes := []rune(cmd.Cmd)
			padding := strings.Repeat(" ", maxCmd-len(runes))
			coloured := colourCmd(cmd.Cmd) + padding
			if cmd.URL != "" {
				coloured = u.Link(coloured, cmd.URL)
			}
			line := coloured +
				"  " + sepStyle.Render(u.icons.Bullet) + "  " +
				descStyle.Render(cmd.Desc)
			u.line(lipgloss.NewStyle().PaddingLeft(u.indent + 2).Render(line))
		}
		u.blank()
	}

	u.Flush()
}

// ─────────────────────────────────────────────
//  Directory tree
// ─────────────────────────────────────────────

type TreeNode struct {
	Label    string
	Value    string
	URL      string
	Icon     string
	Children []TreeNode
}

func (u *UI) Tree(root string, nodes []TreeNode) {
	rootStyle := u.s(u.theme.Accent).Bold(true)
	enumStyle := lipgloss.NewStyle().Foreground(u.theme.Border).MarginRight(1)
	itemStyle := lipgloss.NewStyle().Foreground(u.theme.Primary)
	annotStyle := lipgloss.NewStyle().Foreground(u.theme.Secondary)

	var build func(nodes []TreeNode) *tree.Tree
	build = func(nodes []TreeNode) *tree.Tree {
		t := tree.New()
		for _, n := range nodes {
			label := n.Label
			if n.Icon != "" {
				label = n.Icon + " " + label
			}
			if n.URL != "" {
				label = u.LinkInline(label, n.URL)
			}
			if n.Value != "" {
				label += "  " + annotStyle.Render(n.Value)
			}
			if len(n.Children) > 0 {
				sub := build(n.Children)
				t.Child(sub.Root(label))
			} else {
				t.Child(label)
			}
		}
		return t
	}

	t := build(nodes)
	t.Root(root).
		Enumerator(tree.RoundedEnumerator).
		EnumeratorStyle(enumStyle).
		ItemStyle(itemStyle).
		RootStyle(rootStyle)

	u.blank()
	u.indented(t.String())
	u.blank()
	u.Flush()
}

// TreeWithFiles renders a directory tree with clickable file links.
func (u *UI) TreeWithFiles(rootPath string, nodes []TreeNode) {
	rootStyle := u.s(u.theme.Accent).Bold(true)
	enumStyle := lipgloss.NewStyle().Foreground(u.theme.Border).MarginRight(1)
	itemStyle := lipgloss.NewStyle().Foreground(u.theme.Primary)
	annotStyle := lipgloss.NewStyle().Foreground(u.theme.Secondary)

	var build func(parentPath string, nodes []TreeNode) *tree.Tree
	build = func(parentPath string, nodes []TreeNode) *tree.Tree {
		t := tree.New()
		for _, n := range nodes {
			fullPath := filepath.Join(parentPath, n.Label)
			label := n.Label

			// Add icon
			if n.Icon != "" {
				label = n.Icon + " " + label
			}

			// Make files/directories clickable
			isDir := len(n.Children) > 0
			if n.URL != "" {
				label = u.LinkInline(label, n.URL)
			} else {
				label = u.FileLink(fullPath, isDir)
			}

			if n.Value != "" {
				label += "  " + annotStyle.Render(n.Value)
			}

			if len(n.Children) > 0 {
				sub := build(fullPath, n.Children)
				t.Child(sub.Root(label))
			} else {
				t.Child(label)
			}
		}
		return t
	}

	t := build(rootPath, nodes)
	t.Root(u.FileLink(rootPath, true)).
		Enumerator(tree.RoundedEnumerator).
		EnumeratorStyle(enumStyle).
		ItemStyle(itemStyle).
		RootStyle(rootStyle)

	u.blank()
	u.indented(t.String())
	u.blank()
	u.Flush()
}

// ─────────────────────────────────────────────
//  Feedback lines
// ─────────────────────────────────────────────

func (u *UI) SuccessLine(msg string) {
	u.indented(u.s(u.theme.Success).Bold(true).Render(u.icons.Success) + "  " +
		u.s(u.theme.Primary).Render(msg))
	u.Flush()
}

func (u *UI) WarnLine(msg string) {
	u.indented(u.s(u.theme.Warn).Render(u.icons.Warning) + "  " +
		u.s(u.theme.Secondary).Render(msg))
	u.Flush()
}

func (u *UI) ErrorHint(problem, hint string) {
	u.blank()
	u.indented(u.s(u.theme.Danger).Bold(true).Render(u.icons.Error) + "  " +
		u.s(u.theme.Primary).Render(problem))
	if hint != "" {
		hintPad := lipgloss.NewStyle().PaddingLeft(u.indent + 3)
		u.line(hintPad.Render(
			u.s(u.theme.Faint).Render(u.icons.Arrow) + "  " +
				u.s(u.theme.Secondary).Render(hint),
		))
	}
	u.blank()
	u.Flush()
}

func (u *UI) InfoLine(msg string) {
	u.indented(u.s(u.theme.Faint).Render(u.icons.Info) + "  " +
		u.s(u.theme.Secondary).Render(msg))
	u.Flush()
}

func (u *UI) Step(state, msg string) {
	var icon string
	var iconStyle lipgloss.Style
	switch strings.ToLower(state) {
	case "ok":
		icon, iconStyle = u.icons.Success, u.s(u.theme.Success)
	case "warn":
		icon, iconStyle = u.icons.Warning, u.s(u.theme.Warn)
	case "fail":
		icon, iconStyle = u.icons.Error, u.s(u.theme.Danger)
	case "skip":
		icon, iconStyle = u.icons.Dash, u.s(u.theme.Faint)
	default:
		icon, iconStyle = u.icons.Bullet, u.s(u.theme.Accent)
	}
	u.indented(iconStyle.Render(icon) + "  " + u.s(u.theme.Secondary).Render(msg))
	u.Flush()
}

func (u *UI) StepWithLink(state, msg, url string) {
	var icon string
	var iconStyle lipgloss.Style
	switch strings.ToLower(state) {
	case "ok":
		icon, iconStyle = u.icons.Success, u.s(u.theme.Success)
	case "warn":
		icon, iconStyle = u.icons.Warning, u.s(u.theme.Warn)
	case "fail":
		icon, iconStyle = u.icons.Error, u.s(u.theme.Danger)
	case "skip":
		icon, iconStyle = u.icons.Dash, u.s(u.theme.Faint)
	default:
		icon, iconStyle = u.icons.Bullet, u.s(u.theme.Accent)
	}
	u.indented(iconStyle.Render(icon) + "  " + u.LinkInline(msg, url))
	u.Flush()
}

// ─────────────────────────────────────────────
//  Init success
// ─────────────────────────────────────────────

func (u *UI) InitSuccess(configFile, adminUser, adminPassword string, nextSteps []string) {
	u.SectionHeader("Configuration initialised")

	u.KeyValueBlock("", []KV{
		{Label: "Config file", Value: configFile},
		{Label: "Admin user", Value: adminUser},
		{Label: "Admin password", Value: u.s(u.theme.Warn).Bold(true).Render(adminPassword)},
	})

	u.indented(u.s(u.theme.Warn).Render(u.icons.Warning + "  Save this password — it will not be shown again."))
	u.blank()

	if len(nextSteps) > 0 {
		u.indented(u.s(u.theme.Secondary).Render("Next steps"))

		l := list.New().
			Enumerator(func(_ list.Items, _ int) string { return u.icons.Bullet }).
			EnumeratorStyle(lipgloss.NewStyle().Foreground(u.theme.Faint).MarginRight(1)).
			ItemStyle(lipgloss.NewStyle().Foreground(u.theme.Accent))
		for _, step := range nextSteps {
			l.Item(step)
		}
		u.indented(l.String())
		u.blank()
	}

	u.Flush()
}

// ─────────────────────────────────────────────
//  Uninstall warning
// ─────────────────────────────────────────────

func (u *UI) UninstallWarning(items []string) {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(u.theme.Danger).
		PaddingLeft(2).
		PaddingRight(2).
		PaddingTop(1).
		PaddingBottom(1)

	l := list.New().
		Enumerator(func(_ list.Items, _ int) string { return u.icons.Bullet }).
		EnumeratorStyle(lipgloss.NewStyle().Foreground(u.theme.Faint).MarginRight(1)).
		ItemStyle(lipgloss.NewStyle().Foreground(u.theme.Secondary))
	for _, item := range items {
		l.Item(item)
	}

	content := u.s(u.theme.Danger).Bold(true).Render(u.icons.Warning+" DANGER — Complete uninstall") +
		"\n\n" + l.String() +
		"\n\n" + u.s(u.theme.Danger).Render("This action cannot be undone.")

	u.blank()
	u.indented(box.Render(content))
	u.blank()
	u.Flush()
}

// ─────────────────────────────────────────────
//  Backup / restore
// ─────────────────────────────────────────────

func (u *UI) BackupStart(encrypted bool) {
	if encrypted {
		u.InfoLine("creating AES-256 encrypted backup…")
	} else {
		u.WarnLine("no password provided — creating unencrypted backup")
	}
}

func (u *UI) BackupDone(path string, fileCount int) {
	u.SuccessLine(fmt.Sprintf("backup complete — %d files → %s", fileCount, path))
}

func (u *UI) RestoreDone(count int) {
	u.SuccessLine(fmt.Sprintf("restore complete — %d files restored", count))
}

// ─────────────────────────────────────────────
//  Misc
// ─────────────────────────────────────────────

func (u *UI) Blank() {
	u.blank()
	u.Flush()
}

func (u *UI) Divider() {
	u.indented(u.s(u.theme.Faint).Render(strings.Repeat(u.icons.Dash, 40)))
	u.Flush()
}

func (u *UI) Theme() Theme {
	return u.theme
}

// Println renders a styled string directly (wrapper for lipgloss.Println).
func (u *UI) Println(s string) {
	lipgloss.Println(s)
}

// Sprint renders a styled string to return as value.
func (u *UI) Sprint(s string) string {
	return lipgloss.Sprint(s)
}
