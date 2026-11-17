# =============================================================================
# Minimal PHP-FPM host
# =============================================================================
# root is relative to the Agbero working directory in this local sample.
# In production use an absolute document root and a private PHP-FPM address.
# PHP is optional; enabling it here is the only change from a static host.

domains = ["localhost"]

route "/" {
  web {
    root    = "."
    listing = true

    php {
      enabled = true
      address = "127.0.0.1:9000"
    }
  }
}