# =============================================================================
# Static SPA with client-side routes
# =============================================================================
# spa = "on" serves index.html for unknown paths so /settings/account works
# after a refresh. Set cache_control only when filenames are fingerprinted.

domains     = ["www.example.com"]
compression = true

route "/" {
  enabled  = "on"
  protocol = "http"

  web {
    enabled       = "on"
    root          = "/var/www/site"
    index         = ["index.html"]
    listing       = "off"
    spa           = "on"
    cache_control = "public, max-age=300"
  }
}
