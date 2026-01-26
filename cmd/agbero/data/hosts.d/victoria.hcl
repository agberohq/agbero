domains = ["victoria.localhost"]

route "/*" {
  backend {
    server {
      address = "http://localhost:9428"
      streaming {
        enabled        = true
        flush_interval = "100ms"
      }
    }
  }
}