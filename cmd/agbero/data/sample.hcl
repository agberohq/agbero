domains = ["localhost"]

route "/" {
  web {
    root = "."
    directory = true
  }
}