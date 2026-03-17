domains = ["markdown.localhost"]

route "/pull" {
  web {
    index = "index.md"

    git {
      enabled = "on"
      id = "olekukonko-sample"
      url = "https://github.com/olekukonko/sample"
      interval = "1m"  // Pull every 1min
    }

    markdown {
      enabled = "on"
      view = "browse"

      highlight {
        enabled = "on"
        theme = "dracula"
      }
    }
  }
}


route "/pull" {
  web {
    index = "index.md"

    git {
      enabled = "on"
      id = "olekukonko-sample"
      url = "https://github.com/olekukonko/sample"
      secret = "${env.GITHUB_WEBHOOK_SECRET}"
    }

    markdown {
      enabled = "on"
      view = "browse"

      highlight {
        enabled = "on"
        theme = "dracula"
      }
    }
  }
}

