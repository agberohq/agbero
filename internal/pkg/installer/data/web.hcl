domains = ["localhost"]

# Enable/disable authentication protection across all routes
# Values: "on" | "off"
protected = "on"

# Main route configuration for root path "/"
route "/" {
  web {
    # Document root directory - serves files from here
    root    = "."

    # Directory listing - allows browsing directories without index files
    # Values: "on" (show listing) | "off" (403 forbidden)
    listing = true

    # Single Page Application (SPA) mode - serves index.html for unmatched routes
    # Essential for React, Vue, Angular apps
    spa     = "on"

    # Markdown rendering configuration
    markdown {
      # Enable markdown file rendering
      # Values: "on" | "off" (show source)
      enabled = "on"

      # Markdown viewing mode
      # Values: "browse" | "normal"
      view    = "browse"

      # Syntax highlighting for code blocks
      highlight {
        # Enable code highlighting
        enabled = "on"

        # Color theme for syntax highlighting
        # Options: "dracula", "github", "monokai", "solarized-dark", etc.
        theme   = "dracula"
      }
    }

    # PHP-FPM configuration - UNCOMMENT if serving PHP applications
    # Requires PHP-FPM to be running separately
    # php {
    #   # FastCGI address of PHP-FPM service
    #   # Examples: "127.0.0.1:9000", "unix:/var/run/php/php8.1-fpm.sock"
    #   address = "127.0.0.1:9000"
    #
    #   # Default PHP file to serve when accessing directories
    #   index   = "index.php"
    # }
  }
}