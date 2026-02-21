domains = ["{{ .Domain }}"]
proxy {
  name   = "tcp-service"
  listen = ":{{ .Port }}"
  backend {
    address = "{{ .Target }}"
  }
}