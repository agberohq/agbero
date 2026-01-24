domains = ["localhost"]

route "/" {
  web {
    root = "/Users/oleku/www/tmp"
    directory = true
  }
}

route "/id" {
  web {
    root = "/Users/oleku/www/id"
  }
}