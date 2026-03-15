package helper

import (
	"fmt"
	"os"
	"os/exec"
)

var knownEditors = map[string]bool{
	"vim": true, "vi": true, "nano": true,
	"micro": true, "code": true, "cat": true,
	"less": true, "more": true,
}

func openWithEditor(filePath, editor string) {
	if editor == "" {
		content, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("failed to read file: %v\n", err)
			return
		}
		fmt.Printf("\033[1;34m%s\033[0m\n\n", filePath)
		fmt.Println(string(content))
		return
	}
	runEditor(editor, filePath)
}

func runEditor(editor, filePath string) {
	if !knownEditors[editor] {
		fmt.Printf("unknown editor %q, falling back to cat\n", editor)
		editor = "cat"
	}
	cmd := exec.Command(editor, filePath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("failed to open editor: %v\n", err)
	}
}
