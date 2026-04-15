package nacm

import (
	"testing"
)

// TestAccessOperationMatches_UnknownOpType directly exercises the default
// branch in accessOperationMatches, which is unreachable through the public
// Enforce API because ruleTypeMatches rejects unknown OperationType values
// before accessOperationMatches is ever called.
func TestAccessOperationMatches_UnknownOpType(t *testing.T) {
	t.Parallel()
	if accessOperationMatches("exec read", OperationType(99)) {
		t.Fatal("accessOperationMatches must return false for unknown OperationType")
	}
}
