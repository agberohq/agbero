domains = ["{{ .Domain }}"]
route {
  path = "/"
  web {
    root    = "{{ .Target }}"
    listing = true
  }
}