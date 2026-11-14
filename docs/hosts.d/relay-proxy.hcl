# =============================================================================
# Replay relay mode (client supplies the target)
# =============================================================================
# The client sends X-Agbero-Replay-Url or ?url=. allowed_domains is mandatory
# and private/loopback addresses remain blocked regardless of this list.

domains = ["relay.example.com"]

route "/relay" {
  enabled  = "on"
  protocol = "http"

  serverless {
    enabled = "on"

    replay "public-apis" {
      enabled = "on"
      method  = "GET"
      timeout = "20s"

      allowed_domains = [
        "api.github.com",
        "*.sendgrid.com",
      ]

      headers = {
        "Authorization" = "Bearer ss://integrations/relay-token"
      }
    }
  }
}
