package checks

// Status represents the outcome of a security check.
type Status int

const (
	StatusPass   Status = iota // Green  — compliant
	StatusFail                 // Red    — non-compliant
	StatusWarn                 // Yellow — partial / degraded
	StatusManual               // Blue   — requires manual review
	StatusError                // grey   — check could not run
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusFail:
		return "FAIL"
	case StatusWarn:
		return "WARN"
	case StatusManual:
		return "MANUAL"
	default:
		return "ERROR"
	}
}

// Result is what a check returns after running.
type Result struct {
	Status Status
	Output string // human-readable finding
}

// FixInfo describes the remediation for a failing check.
type FixInfo struct {
	Command       string
	RequiresAdmin bool
	Description   string
}

// Check is the interface every security check must satisfy.
type Check interface {
	CISID()       string
	Name()        string
	Section()     string
	Category()    string
	Severity()    string
	Description() string
	Remediation() string
	IsManual()    bool
	Run()         Result
	Fix()         *FixInfo // nil if not auto-fixable
}

// CheckResult pairs a Check with its Result after execution.
type CheckResult struct {
	Check  Check
	Result Result
}
