# =============================================================================
# On-demand serverless worker
# =============================================================================
# Clients POST to /tools/pdf. Agbero pipes the request body to stdin and
# streams stdout back. The command is not exposed as a general shell: only
# the configured endpoint/path reaches it.

domains = ["tools.example.com"]

route "/tools" {
  enabled  = "on"
  protocol = "http"

  serverless {
    enabled = "on"

    work "pdf" {
      command = ["wkhtmltopdf", "--quiet", "-", "-"]
      timeout = "30s"
    }

    work "thumbnail" {
      command = ["convert", "-", "-thumbnail", "320x320", "-"]
      timeout = "15s"
    }
  }
}
