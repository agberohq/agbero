package ui

import (
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
)

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

// New creates a new UI instance with optional configuration.
// Defaults to stdout, default theme, default icons, and indent 3.
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

func (u *UI) s(c compat.AdaptiveColor) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(c)
}

func (u *UI) padStyle() lipgloss.Style {
	return lipgloss.NewStyle().PaddingLeft(u.indent)
}

func (u *UI) line(s string)     { u.buf.WriteString(s + "\n") }
func (u *UI) indented(s string) { u.line(u.padStyle().Render(s)) }
func (u *UI) blank()            { u.line("") }

// Flush writes all buffered content to the output writer.
// Resets the internal buffer after writing.
func (u *UI) Flush() {
	lipgloss.Fprint(u.w, u.buf.String())
	u.buf.Reset()
}

// String returns the current buffered content as a string.
// Does not flush or modify the buffer.
func (u *UI) String() string { return u.buf.String() }

// Reset clears the internal buffer without flushing.
// Discards any pending output.
func (u *UI) Reset() { u.buf.Reset() }

// Link creates an OSC 8 hyperlink with fallback to plain text.
// Returns the text as a clickable link when terminal supports it.
func (u *UI) Link(text, url string) string {
	if !u.supportsHyperlinks {
		return text
	}
	return lipgloss.NewStyle().Hyperlink(url).Render(text)
}

// LinkInline creates a styled hyperlink with accent color and underline.
// Falls back to styled text without hyperlink if unsupported.
func (u *UI) LinkInline(text, url string) string {
	if !u.supportsHyperlinks {
		return u.s(u.theme.Accent).Underline(true).Render(text)
	}
	return u.s(u.theme.Accent).Underline(true).Hyperlink(url).Render(text)
}

// FileLink creates a clickable file/directory link using file:// protocol.
// Returns bold styling for directories, accent color for files.
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

	if !u.supportsHyperlinks {
		return style.Render(path)
	}
	return style.Hyperlink(url).Render(path)
}

// Welcome displays the application welcome banner with name and description.
// Shows version, date, and optional ASCII art banner.
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

// SectionHeader renders a visually distinct section title with accent bar.
// Converts label to uppercase for emphasis.
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

type KV struct {
	Label string
	Value string
}

// KeyValueBlock renders a formatted block of key-value pairs.
// Automatically aligns labels and adds visual separators.
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

// KeyValue renders a single key-value pair.
// Convenience wrapper around KeyValueBlock.
func (u *UI) KeyValue(label, value string) {
	u.KeyValueBlock("", []KV{{Label: label, Value: value}})
}

// KeyValueLink renders a key-value pair where the value is a clickable link.
// Uses LinkInline for hyperlink styling.
func (u *UI) KeyValueLink(label, text, url string) {
	u.KeyValue(label, u.LinkInline(text, url))
}

// KeyValueFile renders a key-value pair where the value is a clickable file path.
// Uses FileLink for file:// protocol hyperlink.
func (u *UI) KeyValueFile(label, path string, isDir bool) {
	u.KeyValue(label, u.FileLink(path, isDir))
}

// SecretBox renders a sensitive value with a bordered box or plain display.
// Long secrets (>60 chars) use plain display to avoid border breakage.
func (u *UI) SecretBox(label, value string) {
	if len(value) > 60 {
		u.blank()
		u.indented(u.s(u.theme.Accent).Bold(true).Render(u.icons.Key + " " + label))
		u.line("")
		u.indented(u.s(u.theme.Value).Render(value))
		u.blank()
		u.Flush()
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
	u.Flush()
}

// StatusBadge renders a status indicator with colored dot and text.
// Maps status strings to appropriate theme colors.
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

// ServiceStatus renders a complete service status section.
// Includes status badge, PID, and config file path.
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

// Table renders a formatted table with headers and rows.
// Uses rounded borders and theme-appropriate colors.
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

// TableWithLinks renders a table where cells can be clickable hyperlinks.
// Converts LinkCell types to styled hyperlinks automatically.
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

type HelpCmd struct {
	Cmd  string
	Desc string
	URL  string
}

type HelpSection struct {
	Title    string
	Commands []HelpCmd
}

// HelpScreen renders an interactive help screen with categorized commands.
// Automatically aligns command columns and adds hyperlinks when provided.
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

type TreeNode struct {
	Label    string
	Value    string
	URL      string
	Icon     string
	Children []TreeNode
}

// Tree renders a hierarchical tree structure with optional icons and links.
// Uses rounded enumerators and theme-appropriate styling.
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
// Each node becomes a clickable file:// hyperlink to the actual file path.
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

			if n.Icon != "" {
				label = n.Icon + " " + label
			}

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

// SuccessLine renders a success message with a checkmark icon.
// Uses theme success colors for emphasis.
func (u *UI) SuccessLine(msg string) {
	u.indented(u.s(u.theme.Success).Bold(true).Render(u.icons.Success) + "  " +
		u.s(u.theme.Primary).Render(msg))
	u.Flush()
}

// WarnLine renders a warning message with a warning icon.
// Uses theme warn colors for visibility.
func (u *UI) WarnLine(msg string) {
	u.indented(u.s(u.theme.Warn).Render(u.icons.Warning) + "  " +
		u.s(u.theme.Secondary).Render(msg))
	u.Flush()
}

// ErrorHint renders an error message with an optional hint for resolution.
// Shows problem prominently with a hint arrow on the next line.
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

// InfoLine renders an informational message with an info icon.
// Uses faint theme colors for subtle presentation.
func (u *UI) InfoLine(msg string) {
	u.indented(u.s(u.theme.Faint).Render(u.icons.Info) + "  " +
		u.s(u.theme.Secondary).Render(msg))
	u.Flush()
}

// Step renders a step status message with state-based icon and color.
// States: ok, warn, fail, skip, or default bullet.
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

// StepWithLink renders a step status message where the text is a clickable link.
// Combines step state styling with hyperlink functionality.
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

// InitSuccess renders the post-initialization success screen.
// Shows config file, admin credentials, and next steps.
func (u *UI) InitSuccess(configFile, adminUser, adminPassword string, nextSteps []ListItem) {
	u.SectionHeader("Configuration initialised")

	u.KeyValueBlock("", []KV{
		{Label: "Config file", Value: u.FileLink(configFile, false)},
		{Label: "Admin user", Value: adminUser},
		{Label: "Admin password", Value: u.s(u.theme.Warn).Bold(true).Render(adminPassword)},
	})

	u.indented(u.s(u.theme.Warn).Render(u.icons.Warning + "  Save this password — it will not be shown again."))
	u.blank()

	if len(nextSteps) > 0 {
		u.LinkList("Next steps", nextSteps)
	}

	u.Flush()
}

// BackupStart indicates the start of a backup operation.
// Shows encryption status if applicable.
func (u *UI) BackupStart(encrypted bool) {
	if encrypted {
		u.InfoLine("creating AES-256 encrypted backup…")
	} else {
		u.WarnLine("no password provided — creating unencrypted backup")
	}
}

// BackupDone renders completion status for a backup operation.
// Shows file count and destination path.
func (u *UI) BackupDone(path string, fileCount int) {
	u.SuccessLine(fmt.Sprintf("backup complete — %d files → %s", fileCount, path))
}

// RestoreDone renders completion status for a restore operation.
// Shows the number of files restored.
func (u *UI) RestoreDone(count int) {
	u.SuccessLine(fmt.Sprintf("restore complete — %d files restored", count))
}

// Blank outputs a single blank line.
// Useful for adding spacing between UI sections.
func (u *UI) Blank() {
	u.blank()
	u.Flush()
}

// Divider renders a horizontal divider line.
// Uses theme faint color and dash icon repeated.
func (u *UI) Divider() {
	u.indented(u.s(u.theme.Faint).Render(strings.Repeat(u.icons.Dash, 40)))
	u.Flush()
}

// Theme returns the current theme configuration.
// Useful for accessing theme colors outside the UI.
func (u *UI) Theme() Theme {
	return u.theme
}

// Println renders a styled string directly using lipgloss.
// Wrapper for lipgloss.Println with no indentation.
func (u *UI) Println(s string) {
	lipgloss.Println(s)
}

// Sprint renders a styled string and returns it as a value.
// Useful for capturing styled output without printing.
func (u *UI) Sprint(s string) string {
	return lipgloss.Sprint(s)
}

// Image renders raw PNG bytes to the terminal using go-termimg.
// Falls back to half-block text if image protocols fail.
func (u *UI) Image(pngData []byte) error {
	u.Flush()

	img, _, err := image.Decode(bytes.NewReader(pngData))
	if err != nil {
		return err
	}

	return termimg.New(img).
		Width(40).
		Height(40).
		Scale(termimg.ScaleFit).
		Print()
}

// QR generates a QR code from content and renders it via go-termimg.
// Returns QRResult with PNG and terminal fallback formats.
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
			u.WarnLine("Image rendering failed; using text QR fallback")
			indentedFallback := u.padStyle().Render(result.Terminal)
			u.line(indentedFallback)
			u.Flush()
		}
	}

	return result
}

type ListItem struct {
	Text string
	URL  string
}

// LinkList renders a bulleted list with optional clickable links.
// Items with URLs become OSC 8 hyperlinks.
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
	u.Flush()
}

type DialogStyle int

const (
	DialogDanger DialogStyle = iota
	DialogWarning
	DialogInfo
	DialogSuccess
)

// DialogBox renders a bordered dialog with title, bulleted items, and footer.
// Style controls border color, icon, and emphasis (Danger/Warning/Info/Success).
func (u *UI) DialogBox(style DialogStyle, title string, items []string, footer string) {
	var borderColor compat.AdaptiveColor
	var icon string
	var iconStyle lipgloss.Style
	var footerStyle lipgloss.Style

	switch style {
	case DialogDanger:
		borderColor = u.theme.Danger
		icon = u.icons.Warning
		iconStyle = u.s(u.theme.Danger)
		footerStyle = u.s(u.theme.Danger)
	case DialogWarning:
		borderColor = u.theme.Warn
		icon = u.icons.Warning
		iconStyle = u.s(u.theme.Warn)
		footerStyle = u.s(u.theme.Secondary)
	case DialogInfo:
		borderColor = u.theme.Accent
		icon = u.icons.Info
		iconStyle = u.s(u.theme.Accent)
		footerStyle = u.s(u.theme.Secondary)
	case DialogSuccess:
		borderColor = u.theme.Success
		icon = u.icons.Success
		iconStyle = u.s(u.theme.Success)
		footerStyle = u.s(u.theme.Secondary)
	default:
		borderColor = u.theme.Border
		icon = u.icons.Bullet
		iconStyle = u.s(u.theme.Primary)
		footerStyle = u.s(u.theme.Secondary)
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
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

	content := iconStyle.Bold(true).Render(icon+" "+title) + "\n\n" + l.String()
	if footer != "" {
		content += "\n\n" + footerStyle.Render(footer)
	}

	u.blank()
	u.indented(box.Render(content))
	u.blank()
	u.Flush()
}

// Confirm prompts for a yes/no confirmation with left-aligned buttons.
// Returns true if user confirms, false otherwise.
func (u *UI) Confirm(prompt string, helpText ...string) (bool, error) {
	u.Flush()

	var value bool
	confirm := huh.NewConfirm().
		Title(prompt).
		WithButtonAlignment(lipgloss.Left).
		Affirmative("Yes").
		Negative("No").
		Value(&value)

	if len(helpText) > 0 && helpText[0] != "" {
		confirm = confirm.Description(helpText[0])
	}

	err := confirm.Run()
	return value, err
}

// ConfirmDefault prompts with a default value preselected.
// DefaultYes=true preselects Yes, false preselects No.
func (u *UI) ConfirmDefault(prompt string, defaultYes bool, helpText ...string) (bool, error) {
	u.Flush()

	var value bool = defaultYes
	confirm := huh.NewConfirm().
		Title(prompt).
		WithButtonAlignment(lipgloss.Left).
		Affirmative("Yes").
		Negative("No").
		Value(&value)

	if len(helpText) > 0 && helpText[0] != "" {
		confirm = confirm.Description(helpText[0])
	}

	err := confirm.Run()
	return value, err
}

type InputConfig struct {
	Title       string
	Placeholder string
	Description string
	Width       int
}

// Input prompts for a single line of text input.
// Returns the entered string or error if cancelled.
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

// withRequired returns a prompter.Option that rejects empty input with the given message.
func withRequired(msg string) prompter.Option {
	return prompter.WithValidator(func(b []byte) error {
		if len(b) == 0 {
			return prompter.ErrValidation{Msg: msg}
		}
		return nil
	})
}

// withMinLength returns a prompter.Option that rejects input shorter than min bytes.
func withMinLength(min int, msg string) prompter.Option {
	return prompter.WithValidator(func(b []byte) error {
		if len(b) < min {
			return prompter.ErrValidation{Msg: msg}
		}
		return nil
	})
}

// buildSecret assembles a themed *prompter.Secret, optionally enabling confirmation mode.
func (u *UI) buildSecret(prompt string, confirm bool, opts []prompter.Option) *prompter.Secret {
	lockIcon := u.s(u.theme.Accent).Render(u.icons.Lock)
	promptStyle := u.s(u.theme.Primary).Bold(true)

	all := append([]prompter.Option{
		prompter.WithFormatter(func(ctx prompter.Context) string {
			p := promptStyle.Render(ctx.Prompt)
			if ctx.IsConfirm {
				p = promptStyle.Render(ctx.Prompt)
			}
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

// Password prompts for a hidden password with themed lock-icon formatting.
// Returns a Result that must be Zero()'d by the caller when done.
func (u *UI) Password(prompt string, opts ...prompter.Option) (*prompter.Result, error) {
	u.Flush()
	return u.buildSecret(prompt, false, opts).Run()
}

// PasswordConfirm prompts for a password and requires it to be entered twice.
func (u *UI) PasswordConfirm(prompt string) (*prompter.Result, error) {
	u.Flush()
	return u.buildSecret(prompt, true, nil).Run()
}

// PasswordRequired prompts for a non-empty password.
func (u *UI) PasswordRequired(prompt string) (*prompter.Result, error) {
	return u.Password(prompt, withRequired("password cannot be empty"))
}

// PasswordMinLength prompts for a password with a minimum length requirement.
func (u *UI) PasswordMinLength(prompt string, minLen int, errorMsg string) (*prompter.Result, error) {
	return u.Password(prompt, withMinLength(minLen, errorMsg))
}

// PasswordConfirmRequired combines confirmation and required validation.
func (u *UI) PasswordConfirmRequired(prompt string) (*prompter.Result, error) {
	u.Flush()
	return u.buildSecret(prompt, true, []prompter.Option{withRequired("password cannot be empty")}).Run()
}

// PasswordWithHint prompts for a password with hint lines below the prompt.
// Pass confirm=true to require the user to enter the value twice.
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
				p = promptStyle.Render(ctx.Prompt)
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

// PasswordRequiredWithHint combines required validation with a descriptive hint.
func (u *UI) PasswordRequiredWithHint(prompt, hint string) (*prompter.Result, error) {
	return u.PasswordWithHint(prompt, hint, false, withRequired("password cannot be empty"))
}

// PasswordConfirmWithHint prompts for a password with confirmation and a hint.
// Requires non-empty input before proceeding to confirmation.
func (u *UI) PasswordConfirmWithHint(prompt, hint string) (*prompter.Result, error) {
	return u.PasswordWithHint(prompt, hint, true, withRequired("passphrase cannot be empty"))
}

type RegistrationResult struct {
	Username     string
	Password     string
	PasswordHash []byte
}

// RegistrationForm prompts for username and password with confirmation.
// Returns registration result with plain password and bcrypt hash.
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

// SimpleUserPass prompts for username and password separately.
// Returns plaintext username and password (caller must zero password when done).
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
