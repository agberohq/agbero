package main

import "github.com/charmbracelet/bubbles/key"

type KeyMap struct {
	Run           key.Binding
	Stop          key.Binding
	FocusURL      key.Binding
	FocusNext     key.Binding
	FocusPrev     key.Binding
	ToggleVerbose key.Binding
	ScrollUp      key.Binding
	ScrollDown    key.Binding
	PageUp        key.Binding
	PageDown      key.Binding
	Quit          key.Binding
	Help          key.Binding
	SaveConfig    key.Binding
	LoadConfig    key.Binding
	ClearLogs     key.Binding
}

func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Run, k.Stop, k.Help, k.Quit}
}

func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Run, k.Stop, k.FocusURL, k.ToggleVerbose},
		{k.FocusNext, k.FocusPrev, k.ScrollUp, k.ScrollDown},
		{k.PageUp, k.PageDown, k.ClearLogs, k.SaveConfig},
		{k.Help, k.Quit},
	}
}

var defaultKeyMap = KeyMap{
	Run: key.NewBinding(
		key.WithKeys("enter", "ctrl+r"),
		key.WithHelp("enter/ctrl+r", "run test"),
	),
	Stop: key.NewBinding(
		key.WithKeys("ctrl+c", "esc"),
		key.WithHelp("ctrl+c/esc", "stop test"),
	),
	FocusURL: key.NewBinding(
		key.WithKeys("ctrl+l"),
		key.WithHelp("ctrl+l", "focus URL"),
	),
	FocusNext: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next field"),
	),
	FocusPrev: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift+tab", "previous field"),
	),
	ToggleVerbose: key.NewBinding(
		key.WithKeys("ctrl+v"),
		key.WithHelp("ctrl+v", "toggle verbose"),
	),
	ScrollUp: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "scroll up"),
	),
	ScrollDown: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "scroll down"),
	),
	PageUp: key.NewBinding(
		key.WithKeys("pgup", "ctrl+u"),
		key.WithHelp("pgup/ctrl+u", "page up"),
	),
	PageDown: key.NewBinding(
		key.WithKeys("pgdown", "ctrl+d"),
		key.WithHelp("pgdown/ctrl+d", "page down"),
	),
	Quit: key.NewBinding(
		key.WithKeys("ctrl+q", "ctrl+c"),
		key.WithHelp("ctrl+q/c", "quit"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	SaveConfig: key.NewBinding(
		key.WithKeys("ctrl+s"),
		key.WithHelp("ctrl+s", "save config"),
	),
	LoadConfig: key.NewBinding(
		key.WithKeys("ctrl+o"),
		key.WithHelp("ctrl+o", "load config"),
	),
	ClearLogs: key.NewBinding(
		key.WithKeys("ctrl+x"),
		key.WithHelp("ctrl+x", "clear logs"),
	),
}
