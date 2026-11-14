# =============================================================================
# Markdown documentation site
# =============================================================================
# Agbero can render Markdown directly; browse mode provides navigation while
# the normal view renders a single document.

domains = ["docs.example.com"]

route "/" {
  enabled  = "on"
  protocol = "http"

  web {
    enabled = "on"
    root    = "/var/www/docs"
    index   = ["index.md", "README.md"]
    listing = "off"

    markdown {
      enabled = "on"
      view    = "browse"

      highlight {
        enabled = "on"
        theme   = "github"
      }
    }
  }
}
