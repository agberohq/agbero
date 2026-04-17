domains = ["markdown.localhost"]

# -----------------------------------------------------------
# Example A: Polling-based deployment
# Agbero pulls from GitHub every minute automatically.
# -----------------------------------------------------------
route "/pull" {
  web {
    index = ["index.md"]

    git {
      enabled  = "on"
      id       = "olekukonko-sample"
      url      = "https://github.com/olekukonko/sample"
      interval = "1m"  # Pull every 1 minute as a fallback
    }

    markdown {
      enabled = "on"
      view    = "browse"

      highlight {
        enabled = "on"
        theme   = "dracula"
      }
    }
  }
}

# -----------------------------------------------------------
# Example B: Webhook-based deployment (push-to-deploy)
# Point your GitHub webhook at:
#   POST /.well-known/agbero/webhook/git/olekukonko-sample
# with the same secret configured below.
# Agbero will deploy immediately on every push.
# -----------------------------------------------------------
route "/webhook" {
  web {
    index = ["index.md"]

    git {
      enabled  = "on"
      id       = "olekukonko-sample-webhook"
      url      = "https://github.com/olekukonko/sample"
      secret   = "${env.GITHUB_WEBHOOK_SECRET}"  # HMAC-SHA256 verification
    }

    markdown {
      enabled = "on"
      view    = "browse"

      highlight {
        enabled = "on"
        theme   = "dracula"
      }
    }
  }
}
