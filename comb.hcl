recursive = true
output_file = "all.txt"
extensions = [".go"]
exclude_dirs {
  items = ["pkg", "lab", "bin", "dist", "assets", "oppor", "docs"]
}
exclude_files {
  items = ["server.log", "agbero"]
}
use_gitignore = true
detailed = false
go_mode = "code"