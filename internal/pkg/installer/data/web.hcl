domains = ["localhost"]
protected = "on"

route "/" {
  web {
    root = "."
    listing = true
     spa = "on"
    # php {
    #   address = "127.0.0.1:9000"
    #   index   = "index.php"
    # }
  }
}