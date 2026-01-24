domains = ["localhost"]

route "/" {
  web {
    root = "/Users/oleku/www/tmp"
    listing = true
  }
}

route "/id" {
  web {
    root = "/Users/oleku/www/id"
  }
}