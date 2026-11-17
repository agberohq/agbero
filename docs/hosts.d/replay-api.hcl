# =============================================================================
# Replay: server-side credential injection
# =============================================================================
# The browser calls Agbero, never the provider. Replay adds the secret from
# env or keeper to the outbound request and streams the provider response
# back. This is for third-party APIs, not your own backend.

domains = ["api.example.com"]

route "/integrations" {
  enabled  = "on"
  protocol = "http"

  jwt_auth {
    enabled = "on"
    secret  = "ss://auth/jwt-secret"
  }

  serverless {
    enabled = "on"

    replay "stripe" {
      enabled = "on"
      url     = "https://api.stripe.com/v1/charges"
      method  = "POST"
      timeout = "20s"

      headers = {
        "Authorization"  = "Bearer ss://integrations/stripe-key"
        "Stripe-Version" = "2024-04-10"
        "Content-Type"   = "application/json"
      }
    }

    replay "github-search" {
      enabled       = "on"
      url           = "https://api.github.com/search/repositories"
      method        = "GET"
      forward_query = true

      headers = {
        "Authorization" = "Bearer ss://integrations/github-token"
        "Accept"        = "application/vnd.github+json"
      }
    }
  }
}
