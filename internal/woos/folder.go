package woos

import "path/filepath"

type Folder string

func (f Folder) String() string                 { return string(f) }
func (f Folder) Abs(configPath string) string   { return ResolveRelative(configPath, string(f)) }
func (f Folder) Name() string                   { return filepath.Base(f.String()) }
func (f Folder) Ensure(configPath string) error { return EnsureDir(f.Abs(configPath), false) }
