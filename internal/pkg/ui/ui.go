package ui

// ui.go — terminal UI renderer for agbero.
//
// Design principles (mirrored from the oja web terminal):
//
// One indent level (default 3).  Every line of output is padded left by
//      u.indent spaces via u.indented().  Nothing prints at column 0 except
//      raw banners.
//
// Sections own their whitespace.  SectionHeader emits blank–header–blank.
//      Leaf methods (SuccessLine, WarnLine, …) emit NO surrounding blank lines
//      and NO flush — the caller decides when a section ends and calls Flush().
//      This eliminates line-by-line flicker and gives callers full control over
//      breathing room.
//
// Semantic color, not cosmetic color.
//        success  → green   (✓)
//        warn     → amber   (⚠)   — system/recoverable warnings only
//        error    → red     (✗)   — user errors and store failures
//        info     → faint   (ℹ)   — neutral context
//        accent   → blue          — labels, section bars, prompts
//
// ui.UI is injected, not constructed per-callsite.  Callers hold one
//      *ui.UI and pass it through; New() is called once at startup.
//
// io.Reader is injectable (WithReader) so Prompt/PromptInline are
//      testable without os.Stdin.

import (
	"bufio"
	"bytes"
	"fmt"
	"image"
	"io"
	"os"
	"path/filepath"
	"strings"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/compat"
	"charm.land/lipgloss/v2/list"
	"charm.land/lipgloss/v2/table"
	"charm.land/lipgloss/v2/tree"
	"github.com/blacktop/go-termimg"
	"github.com/olekukonko/prompter"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// Icon set

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

// Theme

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

// DefaultTheme mirrors the token palette in style.css:
//
//	--accent  #3b82f6  --green #22c55e  --yellow #eab308
//	--red     #ef4444  --text  #c9d8e8  --subtle #5a7490
var DefaultTheme = Theme{
	Primary:   compat.AdaptiveColor{Dark: lipgloss.Color("#c9d8e8"), Light: lipgloss.Color("#1e293b")},
	Secondary: compat.AdaptiveColor{Dark: lipgloss.Color("#5a7490"), Light: lipgloss.Color("#64748b")},
	Faint:     compat.AdaptiveColor{Dark: lipgloss.Color("#3d5068"), Light: lipgloss.Color("#94a3b8")},
	Accent:    compat.AdaptiveColor{Dark: lipgloss.Color("#3b82f6"), Light: lipgloss.Color("#2563eb")},
	Success:   compat.AdaptiveColor{Dark: lipgloss.Color("#22c55e"), Light: lipgloss.Color("#16a34a")},
	Warn:      compat.AdaptiveColor{Dark: lipgloss.Color("#eab308"), Light: lipgloss.Color("#ca8a04")},
	Danger:    compat.AdaptiveColor{Dark: lipgloss.Color("#ef4444"), Light: lipgloss.Color("#dc2626")},
	Value:     compat.AdaptiveColor{Dark: lipgloss.Color("#e8f2ff"), Light: lipgloss.Color("#0f172a")},
	Border:    compat.AdaptiveColor{Dark: lipgloss.Color("#1a2232"), Light: lipgloss.Color("#dde4ed")},
}

// UI struct

type UI struct {
	w                  io.Writer
	r                  io.Reader
	theme              Theme
	icons              IconSet
	indent             int
	buf                strings.Builder
	supportsHyperlinks bool
}

type Option func(*UI)

func WithWriter(w io.Writer) Option { return func(u *UI) { u.w = w } }
func WithReader(r io.Reader) Option { return func(u *UI) { u.r = r } }
func WithTheme(t Theme) Option      { return func(u *UI) { u.theme = t } }
func WithIcons(i IconSet) Option    { return func(u *UI) { u.icons = i } }
func WithIndent(n int) Option       { return func(u *UI) { u.indent = n } }

// New creates a UI instance. Hold one per command surface and reuse it — do
// not call New() inside individual methods.
func New(opts ...Option) *UI {
	u := &UI{
		w:      os.Stdout,
		r:      os.Stdin,
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

// Buffer primitives
//
// These are the only methods that touch u.buf directly.  Everything else
// builds a styled string and calls one of these.

func (u *UI) s(c compat.AdaptiveColor) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(c)
}

func (u *UI) padStyle() lipgloss.Style {
	return lipgloss.NewStyle().PaddingLeft(u.indent)
}

// line appends a raw string + newline to the buffer.  Not for external use.
func (u *UI) line(s string) { u.buf.WriteString(s + "\n") }

// indented appends a left-padded line to the buffer.  This is the standard
// output path — every visible line should flow through here or line().
func (u *UI) indented(s string) { u.line(u.padStyle().Render(s)) }

// blank appends one empty line.  Sections use this to breathe.
func (u *UI) blank() { u.line("") }

// Public flush / buffer control

// Flush writes all buffered content to the output writer in one syscall,
// then resets the buffer.  Callers invoke this once per command cycle — leaf
// methods (SuccessLine, WarnLine, …) do NOT flush themselves.
func (u *UI) Flush() {
	lipgloss.Fprint(u.w, u.buf.String())
	u.buf.Reset()
}

// FlushAfter executes fn(), then flushes.  Useful for grouping a block of
// output into a single write:
//
//	u.FlushAfter(func() {
//	    u.SuccessLine("stored key")
//	    u.InfoLine("42 bytes")
//	})
func (u *UI) FlushAfter(fn func()) {
	fn()
	u.Flush()
}

// String returns the current buffered content without flushing.
func (u *UI) String() string { return u.buf.String() }

// Reset discards pending output without writing it.
func (u *UI) Reset() { u.buf.Reset() }

// Theme returns the current theme.
func (u *UI) Theme() Theme { return u.theme }

// Hyperlinks

func (u *UI) Link(text, url string) string {
	if !u.supportsHyperlinks {
		return text
	}
	return lipgloss.NewStyle().Hyperlink(url).Render(text)
}

func (u *UI) LinkInline(text, url string) string {
	style := u.s(u.theme.Accent).Underline(true)
	if u.supportsHyperlinks {
		return style.Hyperlink(url).Render(text)
	}
	return style.Render(text)
}

func (u *UI) FileLink(path string, isDir bool) string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	url := "file://" + filepath.ToSlash(absPath)
	style := u.s(u.theme.Accent)
	if isDir {
		style = style.Bold(true)
	}
	if u.supportsHyperlinks {
		return style.Hyperlink(url).Render(path)
	}
	return style.Render(path)
}

// SectionHeader renders a visually distinct section opener and flushes.
//
//	▎ SECTION TITLE
func (u *UI) SectionHeader(label string) {
	bar := u.s(u.theme.Accent).Bold(true).Render("▎")
	text := u.s(u.theme.Secondary).Bold(true).Render(strings.ToUpper(label))
	u.blank()
	u.indented(bar + " " + text)
	u.blank()
	u.Flush()
}

// Blank emits one blank line and flushes.  Use between sections or after the
// last line of a command's output.
func (u *UI) Blank() {
	u.blank()
	u.Flush()
}

// Divider renders a horizontal rule.
func (u *UI) Divider() {
	u.indented(u.s(u.theme.Faint).Render(strings.Repeat(u.icons.Dash, 40)))
}

// Status lines
//
// None of these call Flush.  The caller controls when to flush.

// SuccessLine renders a green ✓ line.
//
//	✓  message
func (u *UI) SuccessLine(msg string) {
	u.indented(
		u.s(u.theme.Success).Bold(true).Render(u.icons.Success) + "  " +
			u.s(u.theme.Primary).Render(msg),
	)
}

// ErrorLine renders a red ✗ line.  Use for user errors and store failures.
//
//	✗  message
func (u *UI) ErrorLine(msg string) {
	u.indented(
		u.s(u.theme.Danger).Bold(true).Render(u.icons.Error) + "  " +
			u.s(u.theme.Primary).Render(msg),
	)
}

// WarnLine renders an amber ⚠ line.  Use for recoverable system warnings only
// — not for user input errors (use ErrorLine/ErrorHint for those).
//
//	⚠  message
func (u *UI) WarnLine(msg string) {
	u.indented(
		u.s(u.theme.Warn).Render(u.icons.Warning) + "  " +
			u.s(u.theme.Secondary).Render(msg),
	)
}

// InfoLine renders a faint ℹ line for neutral context.
//
//	ℹ  message
func (u *UI) InfoLine(msg string) {
	u.indented(
		u.s(u.theme.Faint).Render(u.icons.Info) + "  " +
			u.s(u.theme.Secondary).Render(msg),
	)
}

// ErrorHint renders a red ✗ error with an indented → hint on the next line.
//
//	✗  problem
//	     →  hint
func (u *UI) ErrorHint(problem, hint string) {
	u.blank()
	u.indented(
		u.s(u.theme.Danger).Bold(true).Render(u.icons.Error) + "  " +
			u.s(u.theme.Primary).Render(problem),
	)
	if hint != "" {
		hintPad := lipgloss.NewStyle().PaddingLeft(u.indent + 3)
		u.line(hintPad.Render(
			u.s(u.theme.Faint).Render(u.icons.Arrow) + "  " +
				u.s(u.theme.Secondary).Render(hint),
		))
	}
	u.blank()
}

// Step renders a status step with a state-based icon.
//
//	ok   → ✓  green
//	warn → ⚠  amber
//	fail → ✗  red
//	skip → ─  faint
//	""   → •  accent
func (u *UI) Step(state, msg string) {
	icon, style := u.stepIconStyle(state)
	u.indented(style.Render(icon) + "  " + u.s(u.theme.Secondary).Render(msg))
}

// StepWithLink renders a step where the message is a clickable hyperlink.
func (u *UI) StepWithLink(state, msg, url string) {
	icon, style := u.stepIconStyle(state)
	u.indented(style.Render(icon) + "  " + u.LinkInline(msg, url))
}

func (u *UI) stepIconStyle(state string) (string, lipgloss.Style) {
	switch strings.ToLower(state) {
	case "ok":
		return u.icons.Success, u.s(u.theme.Success)
	case "warn":
		return u.icons.Warning, u.s(u.theme.Warn)
	case "fail":
		return u.icons.Error, u.s(u.theme.Danger)
	case "skip":
		return u.icons.Dash, u.s(u.theme.Faint)
	default:
		return u.icons.Bullet, u.s(u.theme.Accent)
	}
}

// StatusBadge renders a coloured status dot + text.
func (u *UI) StatusBadge(status string) {
	lower := strings.ToLower(strings.TrimSpace(status))
	var dot, text lipgloss.Style
	switch lower {
	case "running", "active", "ok":
		dot, text = u.s(u.theme.Success), u.s(u.theme.Success)
	case "stopped", "inactive", "disabled":
		dot, text = u.s(u.theme.Secondary), u.s(u.theme.Secondary)
	case "unknown", "pending", "starting":
		dot, text = u.s(u.theme.Warn), u.s(u.theme.Warn)
	case "error", "failed", "critical":
		dot, text = u.s(u.theme.Danger), u.s(u.theme.Danger)
	default:
		dot, text = u.s(u.theme.Secondary), u.s(u.theme.Primary)
	}
	u.blank()
	u.indented(dot.Render(u.icons.Dot) + "  " + text.Render(lower))
	u.blank()
}

// ServiceStatus renders a complete service status block.
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

// Key-value blocks

type KV struct {
	Label string
	Value string
}

// KeyValueBlock renders a left-aligned table of label │ value pairs.
// Labels are padded to the longest entry; Unicode widths are respected.
//
//	Config file  │  /etc/agbero.hcl
//	Admin user   │  admin
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
}

// KeyValue renders a single key-value pair.
func (u *UI) KeyValue(label, value string) {
	u.KeyValueBlock("", []KV{{Label: label, Value: value}})
}

func (u *UI) KeyValueLink(label, text, url string) {
	u.KeyValue(label, u.LinkInline(text, url))
}

func (u *UI) KeyValueFile(label, path string, isDir bool) {
	u.KeyValue(label, u.FileLink(path, isDir))
}

// Secret box

// SecretBox renders a sensitive value.  Short values (≤60 chars) get a
// rounded border; long values (tokens, hashes) use plain indented display to
// avoid border-wrapping artefacts.
func (u *UI) SecretBox(label, value string) {
	if len(value) > 60 {
		u.blank()
		u.indented(u.s(u.theme.Accent).Bold(true).Render(u.icons.Key + " " + label))
		u.line("")
		u.indented(u.s(u.theme.Value).Render(value))
		u.blank()
		return
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderTopForeground(u.theme.Accent).
		BorderLeftForeground(u.theme.Border).
		BorderRightForeground(u.theme.Border).
		BorderBottomForeground(u.theme.Border).
		Padding(1)
	content := u.s(u.theme.Accent).Bold(true).Render(u.icons.Key+" "+label) +
		"\n\n" +
		u.s(u.theme.Value).Render(value)
	u.blank()
	u.indented(box.Render(content))
	u.blank()
}

// Table

// Table renders a rounded-border table.  Use this for command references,
// file lists, host tables, etc. — not KeyValueBlock, which is for
// metadata-style pairs only.
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
}

type LinkCell struct {
	Text string
	URL  string
}

// TableWithLinks renders a table that supports LinkCell values.
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

// Help screen

type HelpCmd struct {
	Cmd  string
	Desc string
	URL  string
}

type HelpSection struct {
	Title    string
	Commands []HelpCmd
}

// HelpScreen renders a two-column help layout using Table, not KeyValueBlock.
// Each section gets its own header and table so columns are scoped to the
// longest command in that section — not padded against every command globally.
func (u *UI) HelpScreen(sections []HelpSection) {
	u.blank()
	for _, sec := range sections {
		bar := u.s(u.theme.Accent).Bold(true).Render("▎")
		text := u.s(u.theme.Primary).Bold(true).Render(strings.ToUpper(sec.Title))
		u.indented(bar + " " + text)
		u.blank()

		rows := make([][]string, 0, len(sec.Commands))
		for _, cmd := range sec.Commands {
			coloured := u.colourCmd(cmd.Cmd)
			if cmd.URL != "" {
				coloured = u.Link(coloured, cmd.URL)
			}
			rows = append(rows, []string{coloured, cmd.Desc})
		}
		// Render the table at indent+2 so commands sit visually inside the section.
		t := table.New().
			Border(lipgloss.HiddenBorder()).
			StyleFunc(func(row, col int) lipgloss.Style {
				if col == 0 {
					return lipgloss.NewStyle().PaddingRight(2)
				}
				return lipgloss.NewStyle().Foreground(u.theme.Secondary)
			}).
			Rows(rows...)
		u.line(lipgloss.NewStyle().PaddingLeft(u.indent + 2).Render(t.Render()))
		u.blank()
	}
	u.Flush()
}

// colourCmd applies syntax-like colouring to a command string:
//
//	binary  → faint
//	sub     → accent
//	args    → primary bold
//	flags   → warn
func (u *UI) colourCmd(cmd string) string {
	words := strings.Fields(cmd)
	if len(words) == 0 {
		return cmd
	}
	out := make([]string, len(words))
	binIdx := 0
	if words[0] == "sudo" {
		out[0] = u.s(u.theme.Faint).Render(words[0])
		binIdx = 1
	}
	for i, w := range words {
		if i < binIdx {
			continue
		}
		switch i - binIdx {
		case 0:
			out[i] = u.s(u.theme.Faint).Render(w)
		case 1:
			out[i] = u.s(u.theme.Accent).Render(w)
		default:
			if strings.HasPrefix(w, "-") {
				out[i] = u.s(u.theme.Warn).Render(w)
			} else {
				out[i] = u.s(u.theme.Primary).Bold(true).Render(w)
			}
		}
	}
	return strings.Join(out, " ")
}

// Tree

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
		ItemStyle(lipgloss.NewStyle().Foreground(u.theme.Primary)).
		RootStyle(rootStyle)

	u.blank()
	u.indented(t.String())
	u.blank()
}

func (u *UI) TreeWithFiles(rootPath string, nodes []TreeNode) {
	rootStyle := u.s(u.theme.Accent).Bold(true)
	enumStyle := lipgloss.NewStyle().Foreground(u.theme.Border).MarginRight(1)
	annotStyle := lipgloss.NewStyle().Foreground(u.theme.Secondary)

	var build func(parent string, nodes []TreeNode) *tree.Tree
	build = func(parent string, nodes []TreeNode) *tree.Tree {
		t := tree.New()
		for _, n := range nodes {
			full := filepath.Join(parent, n.Label)
			label := n.Label
			if n.Icon != "" {
				label = n.Icon + " " + label
			}
			if n.URL != "" {
				label = u.LinkInline(label, n.URL)
			} else {
				label = u.FileLink(full, len(n.Children) > 0)
			}
			if n.Value != "" {
				label += "  " + annotStyle.Render(n.Value)
			}
			if len(n.Children) > 0 {
				sub := build(full, n.Children)
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
		ItemStyle(lipgloss.NewStyle().Foreground(u.theme.Primary)).
		RootStyle(rootStyle)

	u.blank()
	u.indented(t.String())
	u.blank()
}

// Banner

// Welcome renders the application startup banner.
// Inspired by the oja banner: large brand name + subtitle on the same line,
// version/date in faint below, then a blank separator.
//
//	agbero  — reverse proxy & secret store
//	v0.3.0  ·  2025-01-15
func (u *UI) Welcome(name, description, version, date, banner string) {
	if banner != "" {
		u.line(u.s(u.theme.Accent).Bold(true).Render(banner))
	}
	u.indented(
		u.s(u.theme.Accent).Bold(true).Render(name) +
			"  " +
			u.s(u.theme.Secondary).Render("— "+description),
	)
	u.indented(u.s(u.theme.Faint).Render(version + "  ·  " + date))
	u.blank()
	u.Flush()
}

// Init success

type ListItem struct {
	Text string
	URL  string
}

// InitSuccess renders the post-initialisation screen.
// If adminPassword is empty the password row is omitted entirely — an empty
// highlighted field is more confusing than no field.
func (u *UI) InitSuccess(configFile, adminUser, adminPassword string, nextSteps []ListItem) {
	u.SectionHeader("Configuration initialised")

	pairs := []KV{
		{Label: "Config file", Value: u.FileLink(configFile, false)},
		{Label: "Admin user", Value: adminUser},
	}
	if adminPassword != "" {
		pairs = append(pairs, KV{
			Label: "Admin password",
			Value: u.s(u.theme.Warn).Bold(true).Render(adminPassword),
		})
	}
	u.KeyValueBlock("", pairs)

	if adminPassword != "" {
		u.indented(u.s(u.theme.Warn).Render(
			u.icons.Warning + "  Save this password — it will not be shown again.",
		))
		u.blank()
	}

	if len(nextSteps) > 0 {
		u.LinkList("Next steps", nextSteps)
	}

	u.Flush()
}

// Backup / restore

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

// Link list

// LinkList renders a bulleted list with optional hyperlinks.
func (u *UI) LinkList(title string, items []ListItem) {
	if len(items) == 0 {
		return
	}
	if title != "" {
		u.blank()
		u.indented(u.s(u.theme.Secondary).Render(title))
		u.blank()
	}

	enum := u.s(u.theme.Faint).Render(u.icons.Bullet)
	enumStyle := lipgloss.NewStyle().MarginRight(1)

	l := list.New().
		Enumerator(func(_ list.Items, _ int) string { return enum }).
		EnumeratorStyle(enumStyle).
		ItemStyle(lipgloss.NewStyle().Foreground(u.theme.Accent))

	for _, item := range items {
		content := item.Text
		if item.URL != "" {
			content = u.LinkInline(item.Text, item.URL)
		}
		l.Item(content)
	}

	u.indented(l.String())
	u.blank()
}

// Dialog box

type DialogStyle int

const (
	DialogDanger DialogStyle = iota
	DialogWarning
	DialogInfo
	DialogSuccess
)

// DialogBox renders a bordered dialog with title, bulleted items, and footer.
func (u *UI) DialogBox(style DialogStyle, title string, items []string, footer string) {
	var borderColor compat.AdaptiveColor
	var icon string
	var iconStyle, footerStyle lipgloss.Style

	switch style {
	case DialogDanger:
		borderColor, icon, iconStyle = u.theme.Danger, u.icons.Warning, u.s(u.theme.Danger)
		footerStyle = u.s(u.theme.Danger)
	case DialogWarning:
		borderColor, icon, iconStyle = u.theme.Warn, u.icons.Warning, u.s(u.theme.Warn)
		footerStyle = u.s(u.theme.Secondary)
	case DialogInfo:
		borderColor, icon, iconStyle = u.theme.Accent, u.icons.Info, u.s(u.theme.Accent)
		footerStyle = u.s(u.theme.Secondary)
	case DialogSuccess:
		borderColor, icon, iconStyle = u.theme.Success, u.icons.Success, u.s(u.theme.Success)
		footerStyle = u.s(u.theme.Secondary)
	default:
		borderColor, icon, iconStyle = u.theme.Border, u.icons.Bullet, u.s(u.theme.Primary)
		footerStyle = u.s(u.theme.Secondary)
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		PaddingLeft(2).PaddingRight(2).PaddingTop(1).PaddingBottom(1)

	l := list.New().
		Enumerator(func(_ list.Items, _ int) string { return u.icons.Bullet }).
		EnumeratorStyle(lipgloss.NewStyle().Foreground(u.theme.Faint).MarginRight(1)).
		ItemStyle(lipgloss.NewStyle().Foreground(u.theme.Secondary))
	for _, item := range items {
		l.Item(item)
	}

	content := iconStyle.Bold(true).Render(icon+" "+title) + "\n\n" + l.String()
	if footer != "" {
		content += "\n\n" + footerStyle.Render(footer)
	}

	u.blank()
	u.indented(box.Render(content))
	u.blank()
}

// QR / image

func (u *UI) Image(pngData []byte) error {
	u.Flush()
	img, _, err := image.Decode(bytes.NewReader(pngData))
	if err != nil {
		return err
	}
	return termimg.New(img).Width(40).Height(40).Scale(termimg.ScaleFit).Print()
}

func (u *UI) QR(content string) *QRResult {
	qrCode, err := NewQr(content, QRLevelM)
	if err != nil {
		u.ErrorHint("QR generation failed", err.Error())
		return nil
	}
	result := qrCode.Result(4)
	u.Println("")
	if result != nil && len(result.PNG) > 0 {
		if err := u.Image(result.PNG); err != nil {
			u.WarnLine("image rendering failed — using text QR fallback")
			u.line(u.padStyle().Render(result.Terminal))
		}
	}
	return result
}

// Raw output

func (u *UI) Println(s string)       { lipgloss.Println(s) }
func (u *UI) Sprint(s string) string { return lipgloss.Sprint(s) }

// Confirm / input

// Confirm prompts for yes/no.  Always flush first so buffered output appears
// before the interactive widget.
func (u *UI) Confirm(prompt string, helpText ...string) (bool, error) {
	u.Flush()
	var value bool
	c := huh.NewConfirm().
		Title(prompt).
		WithButtonAlignment(lipgloss.Left).
		Affirmative("Yes").
		Negative("No").
		Value(&value)
	if len(helpText) > 0 && helpText[0] != "" {
		c = c.Description(helpText[0])
	}
	return value, c.Run()
}

func (u *UI) ConfirmDefault(prompt string, defaultYes bool, helpText ...string) (bool, error) {
	u.Flush()
	value := defaultYes
	c := huh.NewConfirm().
		Title(prompt).
		WithButtonAlignment(lipgloss.Left).
		Affirmative("Yes").
		Negative("No").
		Value(&value)
	if len(helpText) > 0 && helpText[0] != "" {
		c = c.Description(helpText[0])
	}
	return value, c.Run()
}

type InputConfig struct {
	Title       string
	Placeholder string
	Description string
	Width       int
}

func (u *UI) Input(cfg InputConfig) (string, error) {
	u.Flush()
	if cfg.Width == 0 {
		cfg.Width = 60
	}
	var value string
	err := huh.NewInput().
		Title(cfg.Title).
		Description(cfg.Description).
		Placeholder(cfg.Placeholder).
		Value(&value).
		WithWidth(cfg.Width).
		Run()
	return value, err
}

// REPL prompt
//
// Prompt and PromptInline both:
//   - flush pending buffer before rendering the prompt
//   - apply u.indent padding (no more column-0 prompts)
//   - read from u.r (injectable, not hardcoded os.Stdin)

// Prompt renders a full-line prompt with an optional description, reads a
// line from u.r, and returns the trimmed input.
func (u *UI) Prompt(prompt string, description ...string) string {
	u.Flush()

	promptStyle := u.s(u.theme.Accent).Bold(true)
	arrowStyle := u.s(u.theme.Faint)

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(u.padStyle().Render(
		promptStyle.Render(prompt) + " " + arrowStyle.Render(u.icons.Arrow),
	))

	if len(description) > 0 && description[0] != "" {
		sb.WriteString("\n")
		sb.WriteString(u.padStyle().Render(
			u.s(u.theme.Faint).Render("  " + description[0]),
		))
	}
	sb.WriteString(" ")

	lipgloss.Fprint(u.w, sb.String())

	reader := bufio.NewReader(u.r)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// PromptInline renders the compact REPL prompt (keeper> style) at the correct
// indent level and reads a line.  It supports basic line editing via raw mode
// (backspace only — for full readline, replace PromptInline with a readline
// library such as github.com/chzyer/readline).
func (u *UI) PromptInline(prompt string) string {
	u.Flush()

	promptStyle := u.s(u.theme.Accent).Bold(true)
	arrowStyle := u.s(u.theme.Faint)

	// Apply indent padding — this is the fix for the column-0 misalignment.
	styled := u.padStyle().Render(
		promptStyle.Render(prompt) + " " + arrowStyle.Render(u.icons.Arrow) + " ",
	)
	lipgloss.Fprint(u.w, styled)

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		// Not a TTY (test / pipe) — read from u.r directly.
		reader := bufio.NewReader(u.r)
		input, _ := reader.ReadString('\n')
		return strings.TrimSpace(input)
	}
	defer term.Restore(fd, oldState)

	var input []byte
	for {
		var b [1]byte
		if _, err := os.Stdin.Read(b[:]); err != nil {
			return ""
		}
		switch b[0] {
		case 3: // Ctrl+C
			fmt.Fprint(u.w, "^C\r\n")
			return ""
		case '\r', '\n':
			// \r moves the cursor to column 0; \n advances to the next line.
			// Without \r, the next indented() call starts at the column where
			// the last typed character landed — producing the deep right-shift
			// visible when the user types a long command.
			fmt.Fprint(u.w, "\r\n")
			return strings.TrimSpace(string(input))
		case 127: // backspace
			if len(input) > 0 {
				input = input[:len(input)-1]
				fmt.Fprint(u.w, "\b \b")
			}
		default:
			if b[0] >= 32 && b[0] <= 126 {
				input = append(input, b[0])
				fmt.Fprint(u.w, string(b[0]))
			}
		}
	}
}

// Password prompts

func withRequired(msg string) prompter.Option {
	return prompter.WithValidator(func(b []byte) error {
		if len(b) == 0 {
			return prompter.ErrValidation{Msg: msg}
		}
		return nil
	})
}

func withMinLength(min int, msg string) prompter.Option {
	return prompter.WithValidator(func(b []byte) error {
		if len(b) < min {
			return prompter.ErrValidation{Msg: msg}
		}
		return nil
	})
}

func (u *UI) buildSecret(prompt string, confirm bool, opts []prompter.Option) *prompter.Secret {
	lockIcon := u.s(u.theme.Accent).Render(u.icons.Lock)
	promptStyle := u.s(u.theme.Primary).Bold(true)

	all := append([]prompter.Option{
		prompter.WithFormatter(func(ctx prompter.Context) string {
			p := promptStyle.Render(ctx.Prompt)
			if ctx.IsRetry && ctx.LastError != nil {
				errStr := u.s(u.theme.Danger).Render("(" + ctx.LastError.Error() + ")")
				return fmt.Sprintf("\n%s  %s %s: ", lockIcon, p, errStr)
			}
			return fmt.Sprintf("\n%s  %s: ", lockIcon, p)
		}),
	}, opts...)

	s := prompter.NewSecret(prompt, all...)
	if confirm {
		s.WithConfirmation("")
	}
	return s
}

func (u *UI) Password(prompt string, opts ...prompter.Option) (*prompter.Result, error) {
	u.Flush()
	return u.buildSecret(prompt, false, opts).Run()
}

func (u *UI) PasswordConfirm(prompt string) (*prompter.Result, error) {
	u.Flush()
	return u.buildSecret(prompt, true, nil).Run()
}

func (u *UI) PasswordRequired(prompt string) (*prompter.Result, error) {
	return u.Password(prompt, withRequired("password cannot be empty"))
}

func (u *UI) PasswordMinLength(prompt string, minLen int, errorMsg string) (*prompter.Result, error) {
	return u.Password(prompt, withMinLength(minLen, errorMsg))
}

func (u *UI) PasswordConfirmRequired(prompt string) (*prompter.Result, error) {
	u.Flush()
	return u.buildSecret(prompt, true, []prompter.Option{withRequired("password cannot be empty")}).Run()
}

func (u *UI) PasswordWithHint(prompt, hint string, confirm bool, opts ...prompter.Option) (*prompter.Result, error) {
	u.Flush()

	lockIcon := u.s(u.theme.Accent).Render(u.icons.Lock)
	promptStyle := u.s(u.theme.Primary).Bold(true)
	arrow := u.s(u.theme.Faint).Render(u.icons.Arrow)

	renderHint := func(h string) string {
		lines := strings.Split(h, "\n")
		out := make([]string, 0, len(lines))
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			out = append(out, lipgloss.NewStyle().
				PaddingLeft(4).
				Foreground(u.theme.Secondary).
				Render(arrow+"  "+l))
		}
		return strings.Join(out, "\n")
	}

	all := append([]prompter.Option{
		prompter.WithFormatter(func(ctx prompter.Context) string {
			p := promptStyle.Render(ctx.Prompt)
			displayHint := hint
			if ctx.IsConfirm {
				displayHint = "Re-enter to verify"
			}
			if ctx.IsRetry && ctx.LastError != nil {
				errStr := u.s(u.theme.Danger).Render("(" + ctx.LastError.Error() + ")")
				base := fmt.Sprintf("\n%s  %s %s", lockIcon, p, errStr)
				if displayHint != "" {
					return base + "\n" + renderHint(displayHint) + "\n"
				}
				return base + ": "
			}
			base := fmt.Sprintf("\n%s  %s", lockIcon, p)
			if displayHint != "" {
				return base + "\n" + renderHint(displayHint) + "\n"
			}
			return base + ": "
		}),
	}, opts...)

	s := prompter.NewSecret(prompt, all...)
	if confirm {
		s.WithConfirmation("")
	}
	return s.Run()
}

func (u *UI) PasswordRequiredWithHint(prompt, hint string) (*prompter.Result, error) {
	return u.PasswordWithHint(prompt, hint, false, withRequired("password cannot be empty"))
}

func (u *UI) PasswordConfirmWithHint(prompt, hint string) (*prompter.Result, error) {
	return u.PasswordWithHint(prompt, hint, true, withRequired("passphrase cannot be empty"))
}

// Registration form

type RegistrationResult struct {
	Username     string
	Password     string
	PasswordHash []byte
}

func (u *UI) RegistrationForm(title, description string) (*RegistrationResult, error) {
	u.Flush()
	u.SectionHeader(title)
	if description != "" {
		u.InfoLine(description)
		u.Blank()
	}

	username, err := u.Input(InputConfig{
		Title:       "Username",
		Description: "Choose a username for admin access",
		Placeholder: "admin",
		Width:       60,
	})
	if err != nil {
		return nil, err
	}
	if username == "" {
		username = "admin"
	}

	passwordResult, err := u.PasswordConfirmWithHint(
		"Password",
		"Choose a strong password (minimum 8 characters)",
	)
	if err != nil {
		return nil, err
	}
	password := passwordResult.String()
	defer passwordResult.Zero()

	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	return &RegistrationResult{
		Username:     username,
		Password:     password,
		PasswordHash: hash,
	}, nil
}

func (u *UI) SimpleUserPass() (username, password string, err error) {
	username, err = u.Input(InputConfig{
		Title:       "Username",
		Description: "Admin username",
		Placeholder: "admin",
	})
	if err != nil {
		return "", "", err
	}
	if username == "" {
		username = "admin"
	}

	passwordResult, err := u.PasswordConfirm("Password")
	if err != nil {
		return "", "", err
	}
	password = passwordResult.String()
	defer passwordResult.Zero()

	return username, password, nil
}
