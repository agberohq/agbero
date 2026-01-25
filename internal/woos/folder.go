package woos

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Standardize permissions here
const (
	DirPerm    = 0755
	FilePerm   = 0644
	SecurePerm = 0700 // For keys/certs
)

type Folder string

func NewFolder(path string) Folder {
	return Folder(path)
}

func MakeFolder(path string, defaultValue Folder) Folder {
	if path == "" {
		return defaultValue
	}
	return NewFolder(path)
}

func (f Folder) IsSet() bool {
	return f != ""
}

// Path returns the absolute path of the folder
// If the folder is relative, it's resolved against the current working directory
func (f Folder) Path() string {
	if filepath.IsAbs(f.String()) {
		return filepath.Clean(f.String())
	}

	// For relative paths, resolve against current working directory
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, f.String())
}

// Read returns the contents of the directory
// Similar to os.ReadDir but returns entries for the folder's path
func (f Folder) Read() ([]fs.DirEntry, error) {
	return os.ReadDir(f.Path())
}

// ReadNames returns just the names of entries in the directory
func (f Folder) ReadNames() ([]string, error) {
	entries, err := f.Read()
	if err != nil {
		return nil, err
	}

	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names, nil
}

// ReadFiles returns only file entries (excluding directories)
func (f Folder) ReadFiles() ([]fs.DirEntry, error) {
	entries, err := f.Read()
	if err != nil {
		return nil, err
	}

	var files []fs.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry)
		}
	}
	return files, nil
}

// ReadDirs returns only directory entries
func (f Folder) ReadDirs() ([]fs.DirEntry, error) {
	entries, err := f.Read()
	if err != nil {
		return nil, err
	}

	var dirs []fs.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry)
		}
	}
	return dirs, nil
}

func (f Folder) Resolve(base Folder, paths ...string) string {
	var startPath string

	if filepath.IsAbs(f.String()) {
		startPath = filepath.Clean(f.String())
	} else {
		// Use base path (which defaults to CWD if empty)
		startPath = filepath.Join(base.Path(), f.String())
	}

	if len(paths) == 0 {
		return startPath
	}

	// Append additional paths
	allPaths := append([]string{startPath}, paths...)
	return filepath.Join(allPaths...)
}

func (f Folder) String() string {
	return string(f)
}

func (f Folder) Abs(base Folder) string {
	// Legacy method - use Path() for new code
	if filepath.IsAbs(f.String()) {
		return f.String()
	}

	// If base is not set, resolve against current directory
	if !base.IsSet() {
		return f.Path()
	}

	// Resolve relative to base folder's absolute path
	return filepath.Join(base.Path(), f.String())
}

func (f Folder) Name() string {
	return filepath.Base(f.Path())
}

func (f Folder) Ensure(base Folder, secure bool) error {
	perm := os.FileMode(DirPerm)
	if secure {
		perm = SecurePerm
	}

	absPath := f.Resolve(base) // Use Resolve instead of Abs for consistency
	return os.MkdirAll(absPath, perm)
}

func (f Folder) Exists(base Folder) bool {
	absPath := f.Resolve(base) // Use Resolve instead of Abs for consistency
	info, err := os.Stat(absPath)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// Additional helper methods

// Join creates a new Folder by joining paths to this folder
func (f Folder) Join(paths ...string) Folder {
	if len(paths) == 0 {
		return f
	}

	// Start with this folder's absolute path
	basePath := f.Path()
	allPaths := append([]string{basePath}, paths...)
	joined := filepath.Join(allPaths...)
	return Folder(joined)
}

// Parent returns the parent folder
func (f Folder) Parent() Folder {
	absPath := f.Path()
	return Folder(filepath.Dir(absPath))
}

// Rel returns the relative path from base to this folder
func (f Folder) Rel(base Folder) (string, error) {
	fAbs := f.Path()
	baseAbs := base.Path()
	return filepath.Rel(baseAbs, fAbs)
}

// Clean returns the cleaned version of the folder path
func (f Folder) Clean() Folder {
	return Folder(filepath.Clean(f.String()))
}

// IsSubdirOf checks if this folder is a subdirectory of the given base
func (f Folder) IsSubdirOf(base Folder) bool {
	fAbs := f.Path()
	baseAbs := base.Path()

	rel, err := filepath.Rel(baseAbs, fAbs)
	if err != nil {
		return false
	}

	// If the relative path starts with "..", it's not a subdirectory
	return rel != ".." && !filepath.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}

// Walk walks the file tree rooted at the folder
func (f Folder) Walk(fn fs.WalkDirFunc) error {
	return filepath.WalkDir(f.Path(), fn)
}

// Glob returns the names of all files matching the pattern
func (f Folder) Glob(pattern string) ([]string, error) {
	fullPattern := filepath.Join(f.Path(), pattern)
	return filepath.Glob(fullPattern)
}

// HasFiles checks if the folder contains any files (excluding directories)
func (f Folder) HasFiles() (bool, error) {
	entries, err := f.Read()
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			return true, nil
		}
	}
	return false, nil
}

// HasSubdirs checks if the folder contains any subdirectories
func (f Folder) HasSubdirs() (bool, error) {
	entries, err := f.Read()
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			return true, nil
		}
	}
	return false, nil
}

// IsEmpty checks if the folder is empty (no files or subdirectories)
func (f Folder) IsEmpty() (bool, error) {
	entries, err := f.Read()
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}
