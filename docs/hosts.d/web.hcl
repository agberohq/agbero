domains = ["localhost"]

route "/" {
  web {
    root = "."
    listing = true
    index   = ["index.php"]

    php {
      address = "127.0.0.1:9000"
    }
  }
}