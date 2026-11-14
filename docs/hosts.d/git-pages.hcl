# =============================================================================
# Git-backed static site
# =============================================================================
# Agbero pulls the repository, builds are intentionally left to the site's
# deploy process, and the web root serves the checked-out files. Webhooks
# are exposed under /.well-known/agbero/webhook/git/<id>.

domains = ["pages.example.com"]

route "/" {
  enabled  = "on"
  protocol = "http"

  web {
    enabled = "on"
    root    = "/var/lib/agbero/sites/pages"
    index   = ["index.html"]
    listing = "off"

    git {
      enabled  = "on"
      id       = "pages"
      url      = "https://github.com/example/pages.git"
      branch   = "main"
      interval = "5m"
    }
  }
}
