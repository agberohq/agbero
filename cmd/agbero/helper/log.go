package helper

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/pkg/ui"
)

type Log struct {
	p *Helper
}

func (l *Log) Tail(configPath string, lines int, follow bool) {
	global, err := LoadGlobal(configPath)
	if err != nil {
		l.p.Logger.Fatal("load config: ", err)
	}
	path := strings.TrimSpace(global.Logging.File.Path)
	if path == "" {
		path = filepath.Join(global.Storage.DataDir.Path(), "logs.d", "agbero.log")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(configPath), path)
	}
	if lines <= 0 {
		lines = 200
	}
	if err := printTail(path, lines); err != nil {
		l.p.Logger.Fatal("read log: ", err)
	}
	if follow {
		followTail(path)
	}
}

func printTail(path string, lines int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	const maxBytes = 8 << 20
	start := info.Size() - maxBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	ring := make([]string, 0, lines)
	for sc.Scan() {
		line := sc.Text()
		if len(ring) == lines {
			copy(ring, ring[1:])
			ring[len(ring)-1] = line
		} else {
			ring = append(ring, line)
		}
	}
	for _, line := range ring {
		fmt.Println(line)
	}
	return sc.Err()
}

func followTail(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return
	}
	ui.New().InfoLine("following " + path + " (Ctrl-C to stop)")
	buf := make([]byte, 32<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])
		}
		if err != nil && err != io.EOF {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}
