domains = ["localhost"]

route "/" {
  web {
    root    = "."
    listing = true

    php {
      enabled = true
      address = "127.0.0.1:9000"
    }
  }
}