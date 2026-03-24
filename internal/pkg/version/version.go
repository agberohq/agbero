package version

import (
	"strconv"
	"strings"
)

// Version represents a semantic version with parsing and comparison capabilities
type Version struct {
	raw        string
	major      int64
	minor      int64
	patch      int64
	preRelease string
	build      string
	valid      bool
}

// NewVersion creates a new Version from a raw string
func NewVersion(raw string) *Version {
	v := &Version{raw: raw}
	v.parse()
	return v
}

// parse extracts version components from raw string
func (v *Version) parse() {
	if v.raw == "" {
		return
	}

	// Step 1: Strip "v." or "v" prefix

	cleaned := strings.TrimSpace(v.raw)
	cleaned = strings.TrimPrefix(cleaned, "v.")
	cleaned = strings.TrimPrefix(cleaned, "v")

	// Step 2: Check if it's a git describe format (has -N-gHASH pattern)
	// Git describe format: 1.2.3-5-gabcdef or 1.2.3-5-gabcdef-dirty
	// Pre-release format: 1.2.3-alpha, 1.2.3-beta.1, etc.
	isGitDescribe := false
	if idx := strings.Index(cleaned, "-"); idx != -1 {
		remainder := cleaned[idx+1:]
		// Check if it matches git describe pattern: number-gHASH
		if strings.Contains(remainder, "-g") {
			parts := strings.SplitN(remainder, "-", 2)
			if len(parts) == 2 && strings.HasPrefix(parts[1], "g") {
				isGitDescribe = true
			}
		}
	}

	// Step 3: Strip git describe suffix if present
	if isGitDescribe {
		if idx := strings.Index(cleaned, "-"); idx != -1 {
			cleaned = cleaned[:idx]
		}
	}

	// Step 4: Handle dev versions
	if cleaned == "" || cleaned == "dev" {
		return
	}

	// Step 5: Split pre-release and build metadata (only if not git describe)
	var base, preRelease, build string

	if !isGitDescribe {
		if idx := strings.IndexAny(cleaned, "-+"); idx != -1 {
			base = cleaned[:idx]
			suffix := cleaned[idx:]

			if strings.Contains(suffix, "+") {
				parts := strings.SplitN(suffix, "+", 2)
				preRelease = strings.TrimPrefix(parts[0], "-")
				build = parts[1]
			} else {
				preRelease = strings.TrimPrefix(suffix, "-")
			}
		} else {
			base = cleaned
		}
	} else {
		base = cleaned
	}

	// Step 6: Parse major.minor.patch
	parts := strings.Split(base, ".")
	if len(parts) < 3 {
		return
	}

	major, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return
	}

	minor, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return
	}

	patch, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return
	}

	v.major = major
	v.minor = minor
	v.patch = patch
	v.preRelease = preRelease
	v.build = build
	v.valid = true
}

// preReleaseWeight returns stability weight (higher = more stable)
func (v *Version) preReleaseWeight() int {
	if v.preRelease == "" {
		return 100
	}

	// Handle numeric pre-releases like rc.1, beta.2, alpha.3
	// Split on first "." to correctly extract base (e.g. "rc.1" -> "rc")
	basePr := strings.SplitN(v.preRelease, ".", 2)[0]

	switch basePr {
	case "rc":
		return 80
	case "beta":
		return 60
	case "alpha":
		return 40
	default:
		return 0
	}
}

// preReleaseNumeric returns the numeric suffix of a pre-release (e.g., "rc.1" -> 1)
func (v *Version) preReleaseNumeric() int {
	if v.preRelease == "" {
		return 0
	}

	if idx := strings.LastIndexAny(v.preRelease, "0123456789"); idx != -1 {
		// Find the start of the number
		start := idx
		for start > 0 && v.preRelease[start-1] >= '0' && v.preRelease[start-1] <= '9' {
			start--
		}
		num, _ := strconv.Atoi(v.preRelease[start : idx+1])
		return num
	}
	return 0
}

// Compare compares this version with another
// Returns:
//
//	1 if v > other (v is newer)
//	0 if v == other
//	-1 if v < other (other is newer)
//	-2 if either version is invalid
func (v *Version) Compare(other *Version) int {
	if !v.valid || !other.valid {
		return -2
	}

	// Compare major
	if v.major != other.major {
		if v.major > other.major {
			return 1
		}
		return -1
	}

	// Compare minor
	if v.minor != other.minor {
		if v.minor > other.minor {
			return 1
		}
		return -1
	}

	// Compare patch
	if v.patch != other.patch {
		if v.patch > other.patch {
			return 1
		}
		return -1
	}

	// Compare pre-release (stable > rc > beta > alpha)
	w1 := v.preReleaseWeight()
	w2 := other.preReleaseWeight()

	if w1 != w2 {
		if w1 > w2 {
			return 1
		}
		return -1
	}

	// If same pre-release type, compare numeric suffixes
	if w1 > 0 && w1 < 100 && v.preRelease != "" && other.preRelease != "" {
		num1 := v.preReleaseNumeric()
		num2 := other.preReleaseNumeric()
		if num1 != num2 {
			if num1 > num2 {
				return 1
			}
			return -1
		}
	}

	return 0
}

// IsNewerThan checks if this version is newer than the other
func (v *Version) IsNewerThan(other *Version) bool {
	return v.Compare(other) == 1
}

// IsOlderThan checks if this version is older than the other
func (v *Version) IsOlderThan(other *Version) bool {
	return v.Compare(other) == -1
}

// Equals checks if versions are equal
func (v *Version) Equals(other *Version) bool {
	return v.Compare(other) == 0
}

// IsValid returns true if version was parsed successfully
func (v *Version) IsValid() bool {
	return v.valid
}

// IsStable returns true if version is not pre-release
func (v *Version) IsStable() bool {
	return v.valid && v.preRelease == ""
}

// IsPreRelease returns true if version is alpha/beta/rc
func (v *Version) IsPreRelease() bool {
	return v.valid && v.preRelease != ""
}

// Clean returns the cleaned version string (without v prefix or git suffix)
func (v *Version) Clean() string {
	if !v.valid {
		return v.raw
	}

	result := v.majorString() + "." + v.minorString() + "." + v.patchString()
	if v.preRelease != "" {
		result += "-" + v.preRelease
	}
	if v.build != "" {
		result += "+" + v.build
	}
	return result
}

// String returns the version as a string (major.minor.patch only, without pre-release or build metadata)
func (v *Version) String() string {
	if !v.valid {
		return v.raw
	}
	result := v.majorString() + "." + v.minorString() + "." + v.patchString()
	return result
}

// FullString returns the complete version with pre-release and build
func (v *Version) FullString() string {
	return v.Clean()
}

// Major returns the major version number
func (v *Version) Major() int64 {
	return v.major
}

// Minor returns the minor version number
func (v *Version) Minor() int64 {
	return v.minor
}

// Patch returns the patch version number
func (v *Version) Patch() int64 {
	return v.patch
}

// PreRelease returns the pre-release identifier
func (v *Version) PreRelease() string {
	return v.preRelease
}

// Build returns the build metadata
func (v *Version) Build() string {
	return v.build
}

// Raw returns the original raw version string
func (v *Version) Raw() string {
	return v.raw
}

// majorString returns major as string
func (v *Version) majorString() string {
	return strconv.FormatInt(v.major, 10)
}

// minorString returns minor as string
func (v *Version) minorString() string {
	return strconv.FormatInt(v.minor, 10)
}

// patchString returns patch as string
func (v *Version) patchString() string {
	return strconv.FormatInt(v.patch, 10)
}

// Satisfies checks if version satisfies a constraint
// Supports: >=, >, =, <=, <
func (v *Version) Satisfies(constraint string) bool {
	if !v.valid {
		return false
	}

	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(constraint, op) {
			target := strings.TrimSpace(constraint[len(op):])
			other := NewVersion(target)
			if !other.IsValid() {
				return false
			}

			cmp := v.Compare(other)
			switch op {
			case ">=":
				return cmp == 1 || cmp == 0
			case "<=":
				return cmp == -1 || cmp == 0
			case ">":
				return cmp == 1
			case "<":
				return cmp == -1
			case "=":
				return cmp == 0
			}
		}
	}

	// Default to exact match
	other := NewVersion(constraint)
	return v.Equals(other)
}

// ShouldUpdate determines if an update is available
// current is the currently installed version
// latest is the available version
func ShouldUpdate(current, latest string) bool {
	cur := NewVersion(current)
	lat := NewVersion(latest)

	// If latest is dev/empty/invalid, no update
	if !lat.IsValid() {
		return false
	}

	// If current is dev/empty/invalid, always update (latest is valid)
	if !cur.IsValid() {
		return true
	}

	// If both are valid, check if latest is newer
	return lat.IsNewerThan(cur)
}

// IsUpdateAvailable is an alias for ShouldUpdate
func IsUpdateAvailable(current, latest string) bool {
	return ShouldUpdate(current, latest)
}

// LatestStable returns the latest stable version from a list
func LatestStable(versions []string) *Version {
	var latest *Version

	for _, v := range versions {
		ver := NewVersion(v)
		if !ver.IsValid() || ver.IsPreRelease() {
			continue
		}

		if latest == nil || ver.IsNewerThan(latest) {
			latest = ver
		}
	}

	return latest
}

// CompareVersions is a convenience function to compare two version strings
func CompareVersions(v1, v2 string) int {
	return NewVersion(v1).Compare(NewVersion(v2))
}
