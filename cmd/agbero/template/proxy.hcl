domains = ["{{ .Domain }}"]
route {
  path = "/"
  backends {
    server {
      address = "{{ .Target }}"
    }
  }
}