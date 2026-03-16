domains = ["markdown.localhost"]

route "/" {
  web {
    root    = "."
    listing = true
    index = "index.md"

    markdown {
      enabled = on
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