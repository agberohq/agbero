domains = ["imigify.localhost"]

route "/api" {
  backend {
    lb_strategy = "round_robin"

    server {
      address = "http://localhost:6060"
      weight  = 3
    }
    server {
      address = "http://localhost:6061"
      weight  = 1
    }
  }
}

route "/support" {
  backend {
    lb_strategy = "random"
    server {
      address = "http://localhost:7060"
    }
    server {
      address = "http://localhost:7061"
    }
  }
}

route "/" {
  web {
    root = "/Users/oleku/www/tmp/ludo"
    directory = true
  }
}