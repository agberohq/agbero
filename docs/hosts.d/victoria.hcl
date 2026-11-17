# =============================================================================
# VictoriaMetrics / VictoriaLogs UI
# =============================================================================
# The UI is an HTTP reverse proxy. Streaming is enabled so long-running query
# or log-tail responses are flushed rather than buffered.

domains = ["victoria.localhost"]

route "/*" {
  backend {
    server {
      address = "http://localhost:9428"
      streaming {
        enabled        = true
        flush_interval = "100ms"
      }
    }
  }
}