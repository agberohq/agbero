domains = ["localhost"]

route "/" {
  web {
    root = "/Users/oleku/www/tmp"
    listing = true
    php {
      enabled = true
      address = "127.0.0.1:9000"
    }
  }
}

route "/id" {
  web {
    root = "/Users/oleku/www/id"
  }
}