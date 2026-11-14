# =============================================================================
# Markdown documentation site
# =============================================================================
# "normal" renders a single Markdown document; switch view to "browse" for a
# navigation sidebar. The highlight theme is a renderer option, not a path.

domains = ["markdown.localhost"]

route "/" {
  web {
    root    = "."
    listing = true
    index = ["index.md"]

    markdown {
      enabled = "on"
      view = "normal" // or browse

      highlight {
        enabled = "on"
        # monokai: A classic high-contrast dark theme.
        # dracula: A widely used, vibrant purple-toned dark theme.
        # solarized-dark: A popular low-contrast theme designed for reduced eye strain.
        # nord: A cool, arctic blue-toned dark theme.
        # "github-dark"
        theme = "dracula"
      }
    }
  }
}