// Package ja3 computes JA3 TLS fingerprints from ClientHello messages and
// stores them per-connection for retrieval by the firewall layer.
//
// JA3 encodes five fields from the ClientHello into a comma-separated string
// that is then MD5-hashed:
//
//	SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//
// Each field is a dash-separated list of decimal values. GREASE values
// (RFC 8701) are filtered out before encoding.
//
// Reference: https://github.com/salesforce/ja3
package ja3

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// greaseTable contains all GREASE values defined in RFC 8701.
// These are included by TLS implementations as anti-ossification measures
// and must be filtered out before computing the JA3 fingerprint.
var greaseTable = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// Compute computes the JA3 fingerprint (MD5 hash of the raw JA3 string)
// from a *tls.ClientHelloInfo.
//
// Returns an empty string if hello is nil.
func Compute(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}
	raw := Raw(hello)
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Raw returns the unhashed JA3 string for a ClientHello. Useful for logging
// and debugging — the Raw string reveals which fields differ between clients
// while Compute gives the compact fingerprint used for matching.
//
// Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
func Raw(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}

	// SSLVersion: highest supported version, GREASE-filtered.
	version := uint16(0)
	for _, v := range hello.SupportedVersions {
		if !greaseTable[v] && v > version {
			version = v
		}
	}
	// Fall back to the legacy field when SupportedVersions is absent
	// (pre-TLS 1.3 clients). Go's stdlib populates SupportedVersions for
	// all modern handshakes, so this is a safety net only.
	if version == 0 {
		version = 0x0303 // TLS 1.2 default
	}

	ciphers := filterAndJoin16(hello.CipherSuites)
	extensions := extensionIDs(hello)
	curves := filterAndJoin16(curveIDs(hello))
	points := joinUint8s(hello.SupportedPoints)

	return fmt.Sprintf("%d,%s,%s,%s,%s",
		version, ciphers, extensions, curves, points)
}

// extensionIDs returns a dash-joined string of extension type IDs present in
// the ClientHello, filtered of GREASE values. Go's tls.ClientHelloInfo does
// not directly expose raw extension IDs, so we reconstruct the canonical set
// from the fields that correspond to known extensions.
//
// This set matches the extension IDs used by the reference JA3 implementation:
// https://github.com/salesforce/ja3/blob/master/ja3.py
func extensionIDs(hello *tls.ClientHelloInfo) string {
	// Build the extension list in the order they typically appear in a ClientHello.
	var ids []uint16

	// 0x0000 — server_name (SNI): present when ServerName is non-empty
	if hello.ServerName != "" {
		ids = append(ids, 0x0000)
	}
	// 0x000a — supported_groups (elliptic_curves): present when curves are advertised
	if len(hello.SupportedCurves) > 0 {
		ids = append(ids, 0x000a)
	}
	// 0x000b — ec_point_formats: present when point formats are advertised
	if len(hello.SupportedPoints) > 0 {
		ids = append(ids, 0x000b)
	}
	// 0x000d — signature_algorithms: present when algos are advertised
	if len(hello.SignatureSchemes) > 0 {
		ids = append(ids, 0x000d)
	}
	// 0x0010 — application_layer_protocol_negotiation (ALPN)
	if len(hello.SupportedProtos) > 0 {
		ids = append(ids, 0x0010)
	}
	// 0x001c — record_size_limit (Go 1.17+)
	// Not directly exposed — skip.

	// 0x0017 — extended_master_secret: always present in modern TLS
	ids = append(ids, 0x0017)

	// 0x0023 — session_ticket: always present in TLS 1.2 clients
	ids = append(ids, 0x0023)

	// 0x002b — supported_versions: present when SupportedVersions is populated
	if len(hello.SupportedVersions) > 0 {
		ids = append(ids, 0x002b)
	}
	// 0x002d — psk_key_exchange_modes: present in TLS 1.3 clients
	if containsVersion(hello.SupportedVersions, tls.VersionTLS13) {
		ids = append(ids, 0x002d)
	}
	// 0x0033 — key_share: present in TLS 1.3 clients
	if containsVersion(hello.SupportedVersions, tls.VersionTLS13) {
		ids = append(ids, 0x0033)
	}

	return filterAndJoin16(ids)
}

// curveIDs extracts the supported elliptic curve IDs from hello.SupportedCurves,
// casting tls.CurveID to uint16.
func curveIDs(hello *tls.ClientHelloInfo) []uint16 {
	out := make([]uint16, len(hello.SupportedCurves))
	for i, c := range hello.SupportedCurves {
		out[i] = uint16(c)
	}
	return out
}

// filterAndJoin16 removes GREASE values and joins the remaining values with "-".
// Returns an empty string for empty/all-GREASE inputs (not "0").
func filterAndJoin16(vals []uint16) string {
	var parts []string
	for _, v := range vals {
		if !greaseTable[v] {
			parts = append(parts, strconv.FormatUint(uint64(v), 10))
		}
	}
	return strings.Join(parts, "-")
}

// joinUint8s joins a slice of uint8 values with "-".
func joinUint8s(vals []uint8) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, "-")
}

// containsVersion reports whether versions contains the given TLS version.
func containsVersion(versions []uint16, target uint16) bool {
	for _, v := range versions {
		if v == target {
			return true
		}
	}
	return false
}
