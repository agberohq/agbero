# =============================================================================
# Minimal static + PHP host
# =============================================================================
# The simplest useful web route. index.php is first, so PHP-FPM handles the
# entry point; root "." is convenient for local development only.

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