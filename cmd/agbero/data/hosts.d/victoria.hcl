domains = ["victoria.localhost"]

route "/*" {
  backend {
    server {
      address = "http://localhost:9428"
    }
  }
}