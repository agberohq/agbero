domains = ["npm.localhost"]

route "/*" {
  backend {
    server {
      address = "http://localhost:5173"
      weight  = 2
    }
  }
}