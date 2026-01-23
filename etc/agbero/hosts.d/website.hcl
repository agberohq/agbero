domains = ["localhost"]


// Root Web
route "/" {
  web {
    root = "/Users/oleku/www/tmp"
  }
}

// Some other web
route "/id" {
  web {
    root = "/Users/oleku/www/id"
  }
}

