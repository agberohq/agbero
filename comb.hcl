recursive = true
output_file = "agbero.txt"
#extensions = [".go",".css",".js",".html",".md",".hcl"]
extensions = [".go", ".s"]
exclude_dirs {
  items = ["lab", "bin", "dist", "assets", "oppor", "docs"]
}
exclude_files {
  items = ["*.log", "*.txt", "agbero"]
}
use_gitignore = true
detailed      = true
go_mode       = "code"
minify        = true
zip           = false