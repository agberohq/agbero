package xudp

import (
	"bytes"
	"strings"
)

// SIP over UDP (RFC 3261):
//
// SIP messages are text-based. The first line is either:
//   Request:  METHOD sip:uri SIP/2.0
//   Response: SIP/2.0 statuscode reason
//
// The Call-ID header uniquely identifies a SIP dialog and persists
// across all messages in a call (INVITEs, re-INVITEs, BYE, etc.).
// Using Call-ID as the session key ensures all messages for the same
// call are routed to the same SIP proxy backend.
//
// We only look at the first 4096 bytes to avoid scanning oversized
// datagrams. SIP headers are line-delimited (\r\n or \n).

const sipMaxScan = 4096

// sipMatcher implements Matcher for SIP/VoIP traffic.
type sipMatcher struct{}

func init() {
	registerMatcher(&sipMatcher{})
}

func (s *sipMatcher) Name() string { return "sip" }

// Match extracts the Call-ID header value from a SIP datagram.
// Returns ("", false) for non-SIP datagrams or missing Call-ID.
func (s *sipMatcher) Match(data []byte) (string, bool) {
	if len(data) < 12 {
		return "", false
	}

	// Quick check: SIP messages start with a method name or "SIP/2.0"
	if !looksLikeSIP(data) {
		return "", false
	}

	limit := len(data)
	if limit > sipMaxScan {
		limit = sipMaxScan
	}

	return extractCallID(data[:limit])
}

// looksLikeSIP does a fast first-byte check to filter non-SIP traffic.
func looksLikeSIP(data []byte) bool {
	// SIP methods start with uppercase ASCII letters
	// SIP responses start with "SIP/"
	if len(data) < 4 {
		return false
	}
	d := data[:4]
	// Responses
	if bytes.HasPrefix(d, []byte("SIP/")) {
		return true
	}
	// Common request methods
	for _, method := range []string{"INVI", "REG", "BYE", "ACK", "OPT", "CANC", "INFO", "SUBS", "NOTI", "REFE", "MESS", "UPDA", "PUBI"} {
		if strings.HasPrefix(string(data), method) {
			return true
		}
	}
	return false
}

// extractCallID scans the SIP headers for the Call-ID header and
// returns its value.
func extractCallID(data []byte) (string, bool) {
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		// Trim \r if present (CRLF line endings)
		line = bytes.TrimRight(line, "\r")

		if len(line) == 0 {
			// Blank line = end of headers
			break
		}

		// Case-insensitive header match for "call-id" and "i" (compact form)
		lower := strings.ToLower(string(line))
		if strings.HasPrefix(lower, "call-id:") || strings.HasPrefix(lower, "i:") {
			idx := bytes.IndexByte(line, ':')
			if idx < 0 {
				continue
			}
			callID := strings.TrimSpace(string(line[idx+1:]))
			if callID != "" {
				return callID, true
			}
		}
	}
	return "", false
}

// IsSIP returns true if data looks like a SIP datagram.
// Exported for tests and health executor.
func IsSIP(data []byte) bool {
	_, ok := (&sipMatcher{}).Match(data)
	return ok
}
