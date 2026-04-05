package version

import (
	"strings"
	"testing"
)

func TestNewVersion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValid bool
		wantMajor int64
		wantMinor int64
		wantPatch int64
		wantPre   string
		wantBuild string
		wantClean string
		wantFull  string
	}{
		{
			name:      "standard semver with v prefix",
			input:     "v1.2.3",
			wantValid: true,
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
			wantPre:   "",
			wantBuild: "",
			wantClean: "1.2.3",
			wantFull:  "1.2.3",
		},
		{
			name:      "standard semver with v. prefix",
			input:     "v.1.2.3",
			wantValid: true,
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
			wantPre:   "",
			wantBuild: "",
			wantClean: "1.2.3",
			wantFull:  "1.2.3",
		},
		{
			name:      "standard semver without prefix",
			input:     "1.2.3",
			wantValid: true,
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
			wantPre:   "",
			wantBuild: "",
			wantClean: "1.2.3",
			wantFull:  "1.2.3",
		},
		{
			name:      "git describe format",
			input:     "1.2.3-5-gabcdef",
			wantValid: true,
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
			wantPre:   "",
			wantBuild: "",
			wantClean: "1.2.3",
			wantFull:  "1.2.3",
		},
		{
			name:      "git describe with dirty suffix",
			input:     "1.2.3-5-gabcdef-dirty",
			wantValid: true,
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
			wantPre:   "",
			wantBuild: "",
			wantClean: "1.2.3",
			wantFull:  "1.2.3",
		},
		{
			name:      "v prefix with git describe",
			input:     "v1.2.3-5-gabcdef",
			wantValid: true,
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
			wantPre:   "",
			wantBuild: "",
			wantClean: "1.2.3",
			wantFull:  "1.2.3",
		},
		{
			name:      "alpha pre-release",
			input:     "v2.0.0-alpha",
			wantValid: true,
			wantMajor: 2,
			wantMinor: 0,
			wantPatch: 0,
			wantPre:   "alpha",
			wantBuild: "",
			wantClean: "2.0.0-alpha",
			wantFull:  "2.0.0-alpha",
		},
		{
			name:      "beta pre-release",
			input:     "v2.0.0-beta",
			wantValid: true,
			wantMajor: 2,
			wantMinor: 0,
			wantPatch: 0,
			wantPre:   "beta",
			wantBuild: "",
			wantClean: "2.0.0-beta",
			wantFull:  "2.0.0-beta",
		},
		{
			name:      "rc pre-release",
			input:     "v2.0.0-rc.1",
			wantValid: true,
			wantMajor: 2,
			wantMinor: 0,
			wantPatch: 0,
			wantPre:   "rc.1",
			wantBuild: "",
			wantClean: "2.0.0-rc.1",
			wantFull:  "2.0.0-rc.1",
		},
		{
			name:      "with build metadata",
			input:     "1.2.3+20230101",
			wantValid: true,
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
			wantPre:   "",
			wantBuild: "20230101",
			wantClean: "1.2.3+20230101",
			wantFull:  "1.2.3+20230101",
		},
		{
			name:      "with pre-release and build",
			input:     "1.2.3-beta+20230101",
			wantValid: true,
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
			wantPre:   "beta",
			wantBuild: "20230101",
			wantClean: "1.2.3-beta+20230101",
			wantFull:  "1.2.3-beta+20230101",
		},
		{
			name:      "dev version",
			input:     "dev",
			wantValid: false,
		},
		{
			name:      "empty string",
			input:     "",
			wantValid: false,
		},
		{
			name:      "invalid format",
			input:     "not-a-version",
			wantValid: false,
		},
		{
			name:      "partial semver",
			input:     "1.2",
			wantValid: false,
		},
		{
			name:      "non-numeric major",
			input:     "a.b.c",
			wantValid: false,
		},
		{
			name:      "v prefix only",
			input:     "v",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVersion(tt.input)

			if v.IsValid() != tt.wantValid {
				t.Errorf("IsValid() = %v, want %v", v.IsValid(), tt.wantValid)
			}

			if tt.wantValid {
				if v.Major() != tt.wantMajor {
					t.Errorf("Major() = %d, want %d", v.Major(), tt.wantMajor)
				}
				if v.Minor() != tt.wantMinor {
					t.Errorf("Minor() = %d, want %d", v.Minor(), tt.wantMinor)
				}
				if v.Patch() != tt.wantPatch {
					t.Errorf("Patch() = %d, want %d", v.Patch(), tt.wantPatch)
				}
				if v.PreRelease() != tt.wantPre {
					t.Errorf("PreRelease() = %s, want %s", v.PreRelease(), tt.wantPre)
				}
				if v.Build() != tt.wantBuild {
					t.Errorf("Build() = %s, want %s", v.Build(), tt.wantBuild)
				}
				if v.Clean() != tt.wantClean {
					t.Errorf("Clean() = %s, want %s", v.Clean(), tt.wantClean)
				}
				if v.FullString() != tt.wantFull {
					t.Errorf("FullString() = %s, want %s", v.FullString(), tt.wantFull)
				}
				if v.String() != tt.wantClean && tt.wantPre == "" {
					expectedStr := tt.wantClean
					if idx := strings.Index(expectedStr, "-"); idx != -1 {
						expectedStr = expectedStr[:idx]
					}
					if idx := strings.Index(expectedStr, "+"); idx != -1 {
						expectedStr = expectedStr[:idx]
					}
					if v.String() != expectedStr {
						t.Errorf("String() = %s, want %s", v.String(), expectedStr)
					}
				}
			} else {
				if v.Raw() != tt.input {
					t.Errorf("Raw() = %s, want %s", v.Raw(), tt.input)
				}
			}
		})
	}
}

func TestVersion_Compare(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		// Basic comparisons
		{"equal versions", "1.2.3", "1.2.3", 0},
		{"newer major", "2.0.0", "1.9.9", 1},
		{"older major", "1.0.0", "2.0.0", -1},
		{"newer minor", "1.2.0", "1.1.9", 1},
		{"older minor", "1.1.0", "1.2.0", -1},
		{"newer patch", "1.2.3", "1.2.2", 1},
		{"older patch", "1.2.2", "1.2.3", -1},

		// Pre-release comparisons
		{"stable vs alpha", "1.0.0", "1.0.0-alpha", 1},
		{"alpha vs beta", "1.0.0-alpha", "1.0.0-beta", -1},
		{"beta vs rc", "1.0.0-beta", "1.0.0-rc", -1},
		{"rc vs stable", "1.0.0-rc", "1.0.0", -1},
		{"alpha vs alpha equal", "1.0.0-alpha", "1.0.0-alpha", 0},
		{"alpha vs beta with same base", "1.0.0-alpha", "1.0.0-beta", -1},

		// Pre-release naming variations
		{"rc.1 vs rc.2", "1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"beta.1 vs beta.2", "1.0.0-beta.1", "1.0.0-beta.2", -1},
		{"alpha.1 vs alpha.2", "1.0.0-alpha.1", "1.0.0-alpha.2", -1},

		// With v prefixes
		{"v prefix both", "v1.2.3", "v1.2.3", 0},
		{"v prefix left", "v2.0.0", "1.9.9", 1},
		{"v prefix right", "1.0.0", "v2.0.0", -1},

		// With git describe suffixes
		{"git describe both", "1.2.3-5-gabcdef", "1.2.3", 0},
		{"git describe newer", "1.2.4-5-gabcdef", "1.2.3", 1},

		// Invalid versions
		{"invalid vs valid", "invalid", "1.0.0", -2},
		{"valid vs invalid", "1.0.0", "invalid", -2},
		{"both invalid", "invalid", "invalid", -2},
		{"dev vs stable", "dev", "1.0.0", -2},
		{"empty vs stable", "", "1.0.0", -2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1 := NewVersion(tt.v1)
			v2 := NewVersion(tt.v2)
			result := v1.Compare(v2)
			if result != tt.expected {
				t.Errorf("Compare(%s, %s) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

func TestVersion_IsNewerThan(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected bool
	}{
		{"2.0.0", "1.0.0", true},
		{"1.0.0", "2.0.0", false},
		{"1.2.0", "1.1.0", true},
		{"1.1.0", "1.2.0", false},
		{"1.2.3", "1.2.2", true},
		{"1.2.2", "1.2.3", false},
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "1.0.0-alpha", true},
		{"1.0.0-alpha", "1.0.0", false},
		{"invalid", "1.0.0", false},
		{"1.0.0", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.v1+" > "+tt.v2, func(t *testing.T) {
			v1 := NewVersion(tt.v1)
			v2 := NewVersion(tt.v2)
			result := v1.IsNewerThan(v2)
			if result != tt.expected {
				t.Errorf("IsNewerThan() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVersion_IsOlderThan(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected bool
	}{
		{"1.0.0", "2.0.0", true},
		{"2.0.0", "1.0.0", false},
		{"1.1.0", "1.2.0", true},
		{"1.2.0", "1.1.0", false},
		{"1.2.2", "1.2.3", true},
		{"1.2.3", "1.2.2", false},
		{"1.0.0", "1.0.0", false},
		{"1.0.0-alpha", "1.0.0", true},
		{"1.0.0", "1.0.0-alpha", false},
		{"invalid", "1.0.0", false},
		{"1.0.0", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.v1+" < "+tt.v2, func(t *testing.T) {
			v1 := NewVersion(tt.v1)
			v2 := NewVersion(tt.v2)
			result := v1.IsOlderThan(v2)
			if result != tt.expected {
				t.Errorf("IsOlderThan() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVersion_Equals(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected bool
	}{
		{"1.2.3", "1.2.3", true},
		{"v1.2.3", "1.2.3", true},
		{"1.2.3-5-gabcdef", "1.2.3", true},
		{"1.2.3-alpha", "1.2.3-alpha", true},
		{"1.2.3-alpha", "1.2.3-beta", false},
		{"1.2.3", "1.2.4", false},
		{"invalid", "invalid", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.v1+" == "+tt.v2, func(t *testing.T) {
			v1 := NewVersion(tt.v1)
			v2 := NewVersion(tt.v2)
			result := v1.Equals(v2)
			if result != tt.expected {
				t.Errorf("Equals() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVersion_IsStable(t *testing.T) {
	tests := []struct {
		version  string
		expected bool
	}{
		{"1.2.3", true},
		{"v1.2.3", true},
		{"1.2.3-5-gabcdef", true},
		{"1.2.3-alpha", false},
		{"1.2.3-beta", false},
		{"1.2.3-rc.1", false},
		{"1.2.3-dev", false},
		{"invalid", false},
		{"dev", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			v := NewVersion(tt.version)
			result := v.IsStable()
			if result != tt.expected {
				t.Errorf("IsStable() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVersion_IsPreRelease(t *testing.T) {
	tests := []struct {
		version  string
		expected bool
	}{
		{"1.2.3", false},
		{"v1.2.3", false},
		{"1.2.3-5-gabcdef", false},
		{"1.2.3-alpha", true},
		{"1.2.3-beta", true},
		{"1.2.3-rc.1", true},
		{"1.2.3-dev", true},
		{"invalid", false},
		{"dev", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			v := NewVersion(tt.version)
			result := v.IsPreRelease()
			if result != tt.expected {
				t.Errorf("IsPreRelease() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVersion_Satisfies(t *testing.T) {
	tests := []struct {
		version    string
		constraint string
		expected   bool
	}{
		// Greater than or equal
		{"2.0.0", ">=1.0.0", true},
		{"1.0.0", ">=1.0.0", true},
		{"0.9.0", ">=1.0.0", false},
		{"2.0.0-alpha", ">=1.0.0", true},

		// Less than or equal
		{"1.0.0", "<=2.0.0", true},
		{"2.0.0", "<=2.0.0", true},
		{"3.0.0", "<=2.0.0", false},

		// Greater than
		{"2.0.0", ">1.0.0", true},
		{"1.0.0", ">1.0.0", false},
		{"1.0.1", ">1.0.0", true},

		// Less than
		{"1.0.0", "<2.0.0", true},
		{"2.0.0", "<2.0.0", false},
		{"1.9.9", "<2.0.0", true},

		// Equal
		{"1.2.3", "=1.2.3", true},
		{"1.2.3", "=1.2.4", false},
		{"v1.2.3", "=1.2.3", true},

		// With pre-release
		{"2.0.0-alpha", ">=2.0.0", false},
		{"2.0.0", ">=2.0.0-alpha", true},
		{"2.0.0-beta", ">=2.0.0-alpha", true},

		// Invalid
		{"invalid", ">=1.0.0", false},
		{"1.0.0", "invalid", false},
		{"invalid", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.version+" satisfies "+tt.constraint, func(t *testing.T) {
			v := NewVersion(tt.version)
			result := v.Satisfies(tt.constraint)
			if result != tt.expected {
				t.Errorf("Satisfies() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestShouldUpdate(t *testing.T) {
	tests := []struct {
		current  string
		latest   string
		expected bool
	}{
		// Normal updates
		{"1.2.3", "1.2.4", true},
		{"1.2.4", "1.2.3", false},
		{"1.2.3", "1.2.3", false},
		{"1.2.3", "2.0.0", true},
		{"2.0.0", "1.2.3", false},

		// With v prefixes
		{"v1.2.3", "v1.2.4", true},
		{"v1.2.4", "v1.2.3", false},

		// With git describe
		{"1.2.3-5-gabcdef", "1.2.4", true},
		{"1.2.4-5-gabcdef", "1.2.3", false},

		// Pre-release updates
		{"1.2.3-alpha", "1.2.3-beta", true},
		{"1.2.3-beta", "1.2.3", true},
		{"1.2.3", "1.2.3-beta", false},
		{"1.2.3-alpha", "1.2.3", true},

		// Dev versions
		{"dev", "1.0.0", true},
		{"", "1.0.0", true},
		{"1.0.0", "dev", false},
		{"dev", "dev", false},

		// Invalid
		{"invalid", "1.0.0", true},
		{"1.0.0", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.current+" -> "+tt.latest, func(t *testing.T) {
			result := ShouldUpdate(tt.current, tt.latest)
			if result != tt.expected {
				t.Errorf("ShouldUpdate() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsUpdateAvailable(t *testing.T) {
	// Alias for ShouldUpdate
	tests := []struct {
		current  string
		latest   string
		expected bool
	}{
		{"1.0.0", "1.0.1", true},
		{"1.0.1", "1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.current+" -> "+tt.latest, func(t *testing.T) {
			result := IsUpdateAvailable(tt.current, tt.latest)
			if result != tt.expected {
				t.Errorf("IsUpdateAvailable() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.2.3", "1.2.3", 0},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"invalid", "1.0.0", -2},
		{"1.0.0", "invalid", -2},
	}

	for _, tt := range tests {
		t.Run(tt.v1+" vs "+tt.v2, func(t *testing.T) {
			result := CompareVersions(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("CompareVersions() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestLatestStable(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		expected string
	}{
		{
			name: "mixed versions",
			versions: []string{
				"v1.0.0-alpha",
				"v1.0.0-beta",
				"v1.0.0-rc.1",
				"v1.0.0",
				"v1.1.0-beta",
				"v1.1.0",
				"v2.0.0-alpha",
			},
			expected: "v1.1.0",
		},
		{
			name: "only pre-release",
			versions: []string{
				"v1.0.0-alpha",
				"v1.0.0-beta",
				"v1.0.0-rc.1",
			},
			expected: "",
		},
		{
			name:     "empty list",
			versions: []string{},
			expected: "",
		},
		{
			name: "only stable",
			versions: []string{
				"v1.0.0",
				"v1.1.0",
				"v2.0.0",
			},
			expected: "v2.0.0",
		},
		{
			name: "with invalid",
			versions: []string{
				"invalid",
				"v1.0.0",
				"dev",
			},
			expected: "v1.0.0",
		},
		{
			name: "with git describe",
			versions: []string{
				"1.0.0-5-gabcdef",
				"1.1.0-3-g1234567",
				"2.0.0",
			},
			expected: "2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LatestStable(tt.versions)
			if tt.expected == "" {
				if result != nil {
					t.Errorf("LatestStable() = %v, want nil", result)
				}
			} else {
				if result == nil {
					t.Errorf("LatestStable() = nil, want version")
				} else if result.Raw() != tt.expected && result.Clean() != tt.expected {
					t.Errorf("LatestStable() = %s, want %s", result.Raw(), tt.expected)
				}
			}
		})
	}
}

func TestVersion_preReleaseWeight(t *testing.T) {
	tests := []struct {
		preRelease string
		expected   int
	}{
		{"", 100},
		{"rc", 80},
		{"rc.1", 80},
		{"rc.2", 80},
		{"beta", 60},
		{"beta.1", 60},
		{"beta.2", 60},
		{"alpha", 40},
		{"alpha.1", 40},
		{"alpha.2", 40},
		{"custom", 0},
		{"dev", 0},
	}

	for _, tt := range tests {
		t.Run(tt.preRelease, func(t *testing.T) {
			v := &Version{preRelease: tt.preRelease, valid: true}
			result := v.preReleaseWeight()
			if result != tt.expected {
				t.Errorf("preReleaseWeight(%s) = %d, want %d", tt.preRelease, result, tt.expected)
			}
		})
	}
}

func TestVersion_Getters(t *testing.T) {
	v := NewVersion("v1.2.3-beta+20230101")

	if v.Major() != 1 {
		t.Errorf("Major() = %d, want 1", v.Major())
	}
	if v.Minor() != 2 {
		t.Errorf("Minor() = %d, want 2", v.Minor())
	}
	if v.Patch() != 3 {
		t.Errorf("Patch() = %d, want 3", v.Patch())
	}
	if v.PreRelease() != "beta" {
		t.Errorf("PreRelease() = %s, want beta", v.PreRelease())
	}
	if v.Build() != "20230101" {
		t.Errorf("Build() = %s, want 20230101", v.Build())
	}
	if v.Raw() != "v1.2.3-beta+20230101" {
		t.Errorf("Raw() = %s, want v1.2.3-beta+20230101", v.Raw())
	}
}

func TestVersion_String(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"v1.2.3-alpha", "1.2.3"},
		{"1.2.3-alpha", "1.2.3"},
		{"v1.2.3+20230101", "1.2.3"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v := NewVersion(tt.input)
			result := v.String()
			if result != tt.expected {
				t.Errorf("String() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestVersion_Clean(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1.2.3", "1.2.3"},
		{"v.1.2.3", "1.2.3"},
		{"1.2.3-5-gabcdef", "1.2.3"},
		{"1.2.3-alpha", "1.2.3-alpha"},
		{"1.2.3-beta+20230101", "1.2.3-beta+20230101"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v := NewVersion(tt.input)
			result := v.Clean()
			if result != tt.expected {
				t.Errorf("Clean() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestVersion_FullString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1.2.3", "1.2.3"},
		{"1.2.3-alpha", "1.2.3-alpha"},
		{"1.2.3-beta+20230101", "1.2.3-beta+20230101"},
		{"v1.2.3-5-gabcdef", "1.2.3"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v := NewVersion(tt.input)
			result := v.FullString()
			if result != tt.expected {
				t.Errorf("FullString() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestVersion_IsValid(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"1.2.3", true},
		{"v1.2.3", true},
		{"1.2.3-alpha", true},
		{"1.2.3-5-gabcdef", true},
		{"dev", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v := NewVersion(tt.input)
			result := v.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}
