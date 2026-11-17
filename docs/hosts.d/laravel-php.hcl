# =============================================================================
# Laravel / PHP-FPM
# =============================================================================
# Laravel's public directory is the web root; PHP handles index.php.
# PHP-FPM should listen on a private address (TCP or a unix socket).
# If PHP-FPM uses a unix socket, use cgi://unix:/run/php/php-fpm.sock.

domains     = ["app.example.com"]
compression = true

tls {
  mode = "letsencrypt"
  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
  }
}

route "/" {
  enabled  = "on"
  protocol = "http"

  web {
    enabled = "on"
    root    = "/var/www/laravel/public"
    index   = ["index.php", "index.html"]
    listing = "off"
    spa     = "off"

    php {
      enabled = "on"
      address = "127.0.0.1:9000"
    }
  }
}
