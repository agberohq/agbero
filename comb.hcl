recursive = true
output_file = "all.txt"
#extensions = [".go",".css",".js",".html"]
extensions = [".go"]
exclude_dirs {
  items = ["lab", "bin", "dist", "assets", "oppor", "docs"]
}
exclude_files {
  items = ["*.log","*.txt","agbero"]
}
use_gitignore = true
detailed = false
go_mode = "code"
minify = false