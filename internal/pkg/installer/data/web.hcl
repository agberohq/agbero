domains = ["localhost"]

route "/" {
  web {
    root = "."
    listing = true

    # php {
    #   address = "127.0.0.1:9000"
    #   index   = "index.php"
    # }
  }
}