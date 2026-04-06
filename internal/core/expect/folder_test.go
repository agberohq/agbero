package expect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewFolder(t *testing.T) {
	tests := []struct {
		name string
		path string
		want Folder
	}{
		{"empty path", "", Folder("")},
		{"relative path", "test", Folder("test")},
		{"absolute path", "/tmp/test", Folder("/tmp/test")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewFolder(tt.path); got != tt.want {
				t.Errorf("NewFolder() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewFolderOr(t *testing.T) {
	defaultFolder := Folder("/default")
	tests := []struct {
		name         string
		path         string
		defaultValue Folder
		want         Folder
	}{
		{"empty path with default", "", defaultFolder, defaultFolder},
		{"non-empty path", "/custom", defaultFolder, Folder("/custom")},
		{"empty path without default", "", "", Folder("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewFolderOr(tt.path, tt.defaultValue); got != tt.want {
				t.Errorf("NewFolderOr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_Make(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(filepath.Join(tmpDir, "test-make"))

	t.Run("make with default permissions", func(t *testing.T) {
		err := testFolder.Make(false)
		if err != nil {
			t.Fatalf("Make() failed: %v", err)
		}
		if _, err := os.Stat(testFolder.Path()); os.IsNotExist(err) {
			t.Error("directory not created")
		}
	})

	t.Run("make with secure permissions", func(t *testing.T) {
		secureFolder := NewFolder(filepath.Join(tmpDir, "test-secure"))
		err := secureFolder.Make(true)
		if err != nil {
			t.Fatalf("Make(true) failed: %v", err)
		}
		info, err := os.Stat(secureFolder.Path())
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != SecurePerm {
			t.Errorf("expected permissions %o, got %o", SecurePerm, info.Mode().Perm())
		}
	})

	t.Run("make with subdirectories", func(t *testing.T) {
		subFolder := NewFolder(filepath.Join(tmpDir, "test-sub"))
		err := subFolder.Make(false, "level1", "level2")
		if err != nil {
			t.Fatalf("Make() with subdirs failed: %v", err)
		}
		expected := filepath.Join(subFolder.Path(), "level1", "level2")
		if _, err := os.Stat(expected); os.IsNotExist(err) {
			t.Error("subdirectory not created")
		}
	})
}

func TestFolder_Init(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(filepath.Join(tmpDir, "test-init"))

	t.Run("init with custom permissions", func(t *testing.T) {
		err := testFolder.Init(0750)
		if err != nil {
			t.Fatalf("Init() failed: %v", err)
		}
		info, err := os.Stat(testFolder.Path())
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0750 {
			t.Errorf("expected permissions 0750, got %o", info.Mode().Perm())
		}
	})

	t.Run("init with subdirectories", func(t *testing.T) {
		subFolder := NewFolder(filepath.Join(tmpDir, "test-init-sub"))
		err := subFolder.Init(0755, "sub1", "sub2")
		if err != nil {
			t.Fatalf("Init() with subdirs failed: %v", err)
		}
		expected := filepath.Join(subFolder.Path(), "sub1", "sub2")
		if _, err := os.Stat(expected); os.IsNotExist(err) {
			t.Error("subdirectory not created")
		}
	})
}

func TestFolder_IsSet(t *testing.T) {
	tests := []struct {
		name string
		f    Folder
		want bool
	}{
		{"empty folder", Folder(""), false},
		{"non-empty folder", Folder("/tmp"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.IsSet(); got != tt.want {
				t.Errorf("IsSet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_Path(t *testing.T) {
	cwd, _ := os.Getwd()
	tests := []struct {
		name string
		f    Folder
		want string
	}{
		{"absolute path", Folder("/tmp/test"), "/tmp/test"},
		{"relative path", Folder("relative"), filepath.Join(cwd, "relative")},
		{"empty path", Folder(""), filepath.Join(cwd, "")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean the expected path for comparison
			want := filepath.Clean(tt.want)
			if got := tt.f.Path(); got != want {
				t.Errorf("Path() = %v, want %v", got, want)
			}
		})
	}
}

func TestFolder_Read(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	// Create test files and directories
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tmpDir, "dir1"), 0755); err != nil {
		t.Fatal(err)
	}

	entries, err := testFolder.Read()
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestFolder_ReadNames(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	names, err := testFolder.ReadNames()
	if err != nil {
		t.Fatalf("ReadNames() failed: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %d", len(names))
	}
}

func TestFolder_ReadFiles(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tmpDir, "dir"), 0755); err != nil {
		t.Fatal(err)
	}

	files, err := testFolder.ReadFiles()
	if err != nil {
		t.Fatalf("ReadFiles() failed: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
	if files[0].Name() != "file.txt" {
		t.Errorf("expected file.txt, got %s", files[0].Name())
	}
}

func TestFolder_ReadDirs(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tmpDir, "dir"), 0755); err != nil {
		t.Fatal(err)
	}

	dirs, err := testFolder.ReadDirs()
	if err != nil {
		t.Fatalf("ReadDirs() failed: %v", err)
	}
	if len(dirs) != 1 {
		t.Errorf("expected 1 directory, got %d", len(dirs))
	}
	if dirs[0].Name() != "dir" {
		t.Errorf("expected dir, got %s", dirs[0].Name())
	}
}

func TestFolder_Resolve(t *testing.T) {
	tmpDir := t.TempDir()
	base := NewFolder(tmpDir)

	tests := []struct {
		name  string
		f     Folder
		base  Folder
		paths []string
		want  string
	}{
		{"absolute path", Folder("/absolute"), base, nil, "/absolute"},
		{"relative path", Folder("relative"), base, nil, filepath.Join(tmpDir, "relative")},
		{"with subpaths", Folder("sub"), base, []string{"path1", "path2"}, filepath.Join(tmpDir, "sub", "path1", "path2")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.f.Resolve(tt.base, tt.paths...)
			if got != tt.want {
				t.Errorf("Resolve() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_String(t *testing.T) {
	f := Folder("/test/path")
	if f.String() != "/test/path" {
		t.Errorf("String() = %v, want /test/path", f.String())
	}
}

func TestFolder_Abs(t *testing.T) {
	tmpDir := t.TempDir()
	base := NewFolder(tmpDir)
	cwd, _ := os.Getwd()

	tests := []struct {
		name string
		f    Folder
		base Folder
		want string
	}{
		{"absolute path", Folder("/absolute"), base, "/absolute"},
		{"relative with base", Folder("relative"), base, filepath.Join(tmpDir, "relative")},
		{"relative without base", Folder("relative"), Folder(""), filepath.Join(cwd, "relative")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Abs(tt.base); got != tt.want {
				t.Errorf("Abs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_Name(t *testing.T) {
	tests := []struct {
		name string
		f    Folder
		want string
	}{
		{"simple path", Folder("/tmp/test"), "test"},
		{"trailing slash", Folder("/tmp/test/"), "test"},
		{"current directory", Folder("."), "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Name(); got != tt.want {
				t.Errorf("Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_Ensure(t *testing.T) {
	tmpDir := t.TempDir()
	base := NewFolder(tmpDir)

	t.Run("ensure with default permissions", func(t *testing.T) {
		f := Folder("test-ensure")
		err := f.Ensure(base, false)
		if err != nil {
			t.Fatalf("Ensure() failed: %v", err)
		}
		expected := filepath.Join(tmpDir, "test-ensure")
		if _, err := os.Stat(expected); os.IsNotExist(err) {
			t.Error("directory not created")
		}
	})

	t.Run("ensure with secure permissions", func(t *testing.T) {
		f := Folder("test-secure")
		err := f.Ensure(base, true)
		if err != nil {
			t.Fatalf("Ensure(true) failed: %v", err)
		}
		expected := filepath.Join(tmpDir, "test-secure")
		info, err := os.Stat(expected)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != SecurePerm {
			t.Errorf("expected permissions %o, got %o", SecurePerm, info.Mode().Perm())
		}
	})
}

func TestFolder_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	base := NewFolder(tmpDir)

	existingDir := filepath.Join(tmpDir, "exists")
	if err := os.Mkdir(existingDir, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		f    Folder
		base Folder
		want bool
	}{
		{"existing directory", Folder("exists"), base, true},
		{"non-existing directory", Folder("not-exists"), base, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Exists(tt.base); got != tt.want {
				t.Errorf("Exists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_ExistsAbsolute(t *testing.T) {
	tmpDir := t.TempDir()
	existingDir := filepath.Join(tmpDir, "exists")
	if err := os.Mkdir(existingDir, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		f    Folder
		want bool
	}{
		{"existing directory", Folder(existingDir), true},
		{"non-existing directory", Folder(filepath.Join(tmpDir, "not-exists")), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.ExistsAbsolute(); got != tt.want {
				t.Errorf("ExistsAbsolute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_FileExists(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	testFile := "test.txt"
	if err := testFolder.Put(testFile, []byte("test"), FilePerm); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		f     Folder
		paths []string
		want  bool
	}{
		{"existing file", testFolder, []string{testFile}, true},
		{"non-existing file", testFolder, []string{"not-exists.txt"}, false},
		{"nested path", testFolder, []string{"sub", "file.txt"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.FileExists(tt.paths...); got != tt.want {
				t.Errorf("FileExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_Sub(t *testing.T) {
	tmpDir := t.TempDir()
	base := NewFolder(tmpDir)

	subFolder := base.Sub("sub1", "sub2")
	expected := filepath.Join(tmpDir, "sub1", "sub2")
	if subFolder.Path() != expected {
		t.Errorf("Sub() = %v, want %v", subFolder.Path(), expected)
	}

	// Test with Folder type
	folderArg := Folder("sub3")
	subFolder2 := base.Sub("sub1", folderArg)
	expected2 := filepath.Join(tmpDir, "sub1", "sub3")
	if subFolder2.Path() != expected2 {
		t.Errorf("Sub() with Folder arg = %v, want %v", subFolder2.Path(), expected2)
	}
}

func TestFolder_Parent(t *testing.T) {
	tmpDir := t.TempDir()
	f := NewFolder(filepath.Join(tmpDir, "child", "grandchild"))
	parent := f.Parent()
	expected := filepath.Join(tmpDir, "child")
	if parent.Path() != expected {
		t.Errorf("Parent() = %v, want %v", parent.Path(), expected)
	}
}

func TestFolder_Rel(t *testing.T) {
	tmpDir := t.TempDir()
	base := NewFolder(tmpDir)
	sub := base.Sub("subdir")

	rel, err := sub.Rel(base)
	if err != nil {
		t.Fatalf("Rel() failed: %v", err)
	}
	if rel != "subdir" {
		t.Errorf("Rel() = %v, want subdir", rel)
	}
}

func TestFolder_Clean(t *testing.T) {
	f := Folder("/tmp//test/../test")
	cleaned := f.Clean()
	expected := Folder("/tmp/test")
	if cleaned != expected {
		t.Errorf("Clean() = %v, want %v", cleaned, expected)
	}
}

func TestFolder_IsSubdirOf(t *testing.T) {
	tmpDir := t.TempDir()
	base := NewFolder(tmpDir)
	sub := base.Sub("subdir")
	other := NewFolder("/other")

	tests := []struct {
		name string
		f    Folder
		base Folder
		want bool
	}{
		{"is subdirectory", sub, base, true},
		{"is not subdirectory", base, sub, false},
		{"different root", sub, other, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.IsSubdirOf(tt.base); got != tt.want {
				t.Errorf("IsSubdirOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFolder_Walk(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	// Create test structure
	if err := testFolder.Put("file1.txt", []byte("test"), FilePerm); err != nil {
		t.Fatal(err)
	}
	subDir := testFolder.Sub("subdir")
	if err := subDir.Init(DirPerm); err != nil {
		t.Fatal(err)
	}
	if err := subDir.Put("file2.txt", []byte("test"), FilePerm); err != nil {
		t.Fatal(err)
	}

	count := 0
	err := testFolder.Walk(func(path string, d os.DirEntry, err error) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("Walk() failed: %v", err)
	}
	// Just verify walk doesn't error and counts something
	if count == 0 {
		t.Error("Walk() didn't process any entries")
	}
}

func TestFolder_Glob(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	if err := testFolder.Put("file1.txt", []byte("test"), FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := testFolder.Put("file2.txt", []byte("test"), FilePerm); err != nil {
		t.Fatal(err)
	}

	matches, err := testFolder.Glob("*.txt")
	if err != nil {
		t.Fatalf("Glob() failed: %v", err)
	}
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
}

func TestFolder_HasFiles(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	t.Run("has files", func(t *testing.T) {
		if err := testFolder.Put("file.txt", []byte("test"), FilePerm); err != nil {
			t.Fatal(err)
		}
		has, err := testFolder.HasFiles()
		if err != nil {
			t.Fatalf("HasFiles() failed: %v", err)
		}
		if !has {
			t.Error("expected HasFiles() to return true")
		}
	})

	t.Run("no files", func(t *testing.T) {
		emptyFolder := NewFolder(filepath.Join(tmpDir, "empty"))
		if err := emptyFolder.Init(DirPerm); err != nil {
			t.Fatal(err)
		}
		has, err := emptyFolder.HasFiles()
		if err != nil {
			t.Fatalf("HasFiles() failed: %v", err)
		}
		if has {
			t.Error("expected HasFiles() to return false")
		}
	})
}

func TestFolder_HasSubdirs(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	t.Run("has subdirs", func(t *testing.T) {
		sub := testFolder.Sub("subdir")
		if err := sub.Init(DirPerm); err != nil {
			t.Fatal(err)
		}
		has, err := testFolder.HasSubdirs()
		if err != nil {
			t.Fatalf("HasSubdirs() failed: %v", err)
		}
		if !has {
			t.Error("expected HasSubdirs() to return true")
		}
	})

	t.Run("no subdirs", func(t *testing.T) {
		emptyFolder := NewFolder(filepath.Join(tmpDir, "empty"))
		if err := emptyFolder.Init(DirPerm); err != nil {
			t.Fatal(err)
		}
		has, err := emptyFolder.HasSubdirs()
		if err != nil {
			t.Fatalf("HasSubdirs() failed: %v", err)
		}
		if has {
			t.Error("expected HasSubdirs() to return false")
		}
	})
}

func TestFolder_IsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	t.Run("empty directory", func(t *testing.T) {
		emptyFolder := testFolder.Sub("empty")
		if err := emptyFolder.Init(DirPerm); err != nil {
			t.Fatal(err)
		}
		empty, err := emptyFolder.IsEmpty()
		if err != nil {
			t.Fatalf("IsEmpty() failed: %v", err)
		}
		if !empty {
			t.Error("expected IsEmpty() to return true")
		}
	})

	t.Run("non-empty directory", func(t *testing.T) {
		nonEmpty := testFolder.Sub("nonempty")
		if err := nonEmpty.Init(DirPerm); err != nil {
			t.Fatal(err)
		}
		if err := nonEmpty.Put("file.txt", []byte("test"), FilePerm); err != nil {
			t.Fatal(err)
		}
		empty, err := nonEmpty.IsEmpty()
		if err != nil {
			t.Fatalf("IsEmpty() failed: %v", err)
		}
		if empty {
			t.Error("expected IsEmpty() to return false")
		}
	})
}

func TestFolder_Put(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	filename := "test.txt"
	data := []byte("test content")
	err := testFolder.Put(filename, data, FilePerm)
	if err != nil {
		t.Fatalf("Put() failed: %v", err)
	}

	readData, err := os.ReadFile(filepath.Join(tmpDir, filename))
	if err != nil {
		t.Fatal(err)
	}
	if string(readData) != string(data) {
		t.Errorf("Put() wrote %s, want %s", readData, data)
	}
}

func TestFolder_FilePath(t *testing.T) {
	tmpDir := t.TempDir()
	testFolder := NewFolder(tmpDir)

	tests := []struct {
		name  string
		f     Folder
		paths []string
		want  string
	}{
		{"no paths", testFolder, nil, testFolder.Path()},
		{"single path", testFolder, []string{"file.txt"}, filepath.Join(tmpDir, "file.txt")},
		{"multiple paths", testFolder, []string{"sub", "file.txt"}, filepath.Join(tmpDir, "sub", "file.txt")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.FilePath(tt.paths...); got != tt.want {
				t.Errorf("FilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
