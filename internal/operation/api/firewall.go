package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// FirewallHandler registers all firewall management API endpoints under the /firewall prefix on the provided chi.Router.
// Caller should apply authentication middleware via r.Use() before or within the route group.
func FirewallHandler(s *Shared, r chi.Router) {
	fw := NewFirewall(s)

	r.Route("/firewall", func(r chi.Router) {
		r.Get("/", fw.list)
		r.Post("/", fw.block)
		r.Delete("/", fw.unblock)
	})
}

// Firewall provides HTTP handlers for IP blocking, unblocking, and rule listing operations.
// It encapsulates the firewall ppk and logger for administrative control.
type Firewall struct {
	shared *Shared
	logger *ll.Logger
}

// NewFirewall initializes a Firewall instance with shared application dependencies.
// It configures the logger namespace and prepares the handler for firewall operations.
func NewFirewall(cfg *Shared) *Firewall {
	return &Firewall{
		shared: cfg,
		logger: cfg.Logger.Namespace("api/firewall"),
	}
}

// list handles GET requests to retrieve all active firewall rules as JSON.
// It returns enabled status and rule list, or disabled status if firewall is not configured.
func (fw *Firewall) list(w http.ResponseWriter, r *http.Request) {
	manager := fw.shared.State().Firewall
	if manager == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"enabled": false,
			"rules":   []string{},
		})
		return
	}

	rules, err := manager.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"enabled": true,
		"rules":   rules,
	})
}

// block handles POST requests to block an IP address or CIDR range with optional metadata.
// It validates input, constructs a reason string, and delegates to the firewall manager.
func (fw *Firewall) block(w http.ResponseWriter, r *http.Request) {
	manager := fw.shared.State().Firewall
	if manager == nil {
		http.Error(w, "firewall is disabled in configuration", http.StatusNotImplemented)
		return
	}

	var req struct {
		IP          string `json:"ip"`
		Reason      string `json:"reason"`
		Host        string `json:"host"`
		Path        string `json:"path"`
		DurationSec int    `json:"duration_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}
	if !isValidIPOrCIDR(req.IP) {
		http.Error(w, "Invalid IP address or CIDR", http.StatusBadRequest)
		return
	}
	dur := time.Duration(req.DurationSec) * time.Second
	reason := buildBlockReason(req.Reason, req.Host, req.Path)
	if err := manager.Block(req.IP, reason, dur); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fw.logger.Fields("ip", req.IP, "reason", reason, "duration", dur).Info("admin: blocked ip")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Blocked"))
}

// unblock handles DELETE requests to remove a block rule for an IP address or CIDR range.
// It validates the IP query parameter and delegates to the firewall manager.
func (fw *Firewall) unblock(w http.ResponseWriter, r *http.Request) {
	manager := fw.shared.State().Firewall
	if manager == nil {
		http.Error(w, "firewall is disabled in configuration", http.StatusNotImplemented)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "IP query parameter required", http.StatusBadRequest)
		return
	}
	if !isValidIPOrCIDR(ip) {
		http.Error(w, "Invalid IP address or CIDR", http.StatusBadRequest)
		return
	}
	if err := manager.Unblock(ip); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fw.logger.Fields("ip", ip).Info("admin: unblocked ip")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Unblocked"))
}

// isValidIPOrCIDR validates that a string is either a valid IP address or CIDR notation.
// It returns true for IPv4, IPv6, or CIDR blocks; false otherwise.
func isValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// buildBlockReason constructs a descriptive reason string from optional host/path context.
// It appends host and path details in parentheses if provided, otherwise returns base reason.
func buildBlockReason(reason, host, path string) string {
	var details []string
	if host != "" {
		details = append(details, "host="+host)
	}
	if path != "" {
		details = append(details, "path="+path)
	}
	if len(details) > 0 {
		return fmt.Sprintf("%s (%s)", reason, strings.Join(details, ", "))
	}
	return reason
}
