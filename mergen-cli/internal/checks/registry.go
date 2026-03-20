package checks

import (
	"sort"
	"strings"
)

var registry []Check

// Register adds a check to the global registry.
// Called from each section's init().
func Register(c Check) {
	registry = append(registry, c)
}

// All returns every registered check, sorted by CIS ID then name.
func All() []Check {
	sorted := make([]Check, len(registry))
	copy(sorted, registry)
	sort.Slice(sorted, func(i, j int) bool {
		ai, aj := sorted[i].CISID(), sorted[j].CISID()
		if ai == "" && aj == "" {
			return sorted[i].Name() < sorted[j].Name()
		}
		if ai == "" {
			return false
		}
		if aj == "" {
			return true
		}
		return ai < aj
	})
	return sorted
}

// ByCategory returns checks whose Category() matches cat (case-insensitive).
func ByCategory(cat string) []Check {
	if cat == "" {
		return All()
	}
	var out []Check
	for _, c := range All() {
		if strings.EqualFold(c.Category(), cat) {
			out = append(out, c)
		}
	}
	return out
}

// BySection returns checks for a given section number prefix (e.g. "1", "2").
func BySection(sec string) []Check {
	var out []Check
	prefix := sec + "."
	for _, c := range All() {
		if strings.HasPrefix(c.CISID(), prefix) || c.CISID() == sec {
			out = append(out, c)
		}
	}
	return out
}
