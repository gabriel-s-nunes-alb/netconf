package nacm_test

import (
	"testing"

	"github.com/GabrielNunesIT/netconf/nacm"
	"github.com/stretchr/testify/assert"
)

// mkProtocolOpRequest builds a Request for a protocol operation.
func mkProtocolOpRequest(user string, groups []string, module, rpc string) nacm.Request {
	return nacm.Request{
		User:          user,
		Groups:        groups,
		OperationType: nacm.OpProtocolOperation,
		OperationName: rpc,
		ModuleName:    module,
	}
}

// mkNotificationRequest builds a Request for a notification delivery check.
// module is always "ietf-netconf-notifications" per the RFC 6470 YANG module.
func mkNotificationRequest(user string, groups []string, notif string) nacm.Request {
	return nacm.Request{
		User:          user,
		Groups:        groups,
		OperationType: nacm.OpNotification,
		OperationName: notif,
		ModuleName:    "ietf-netconf-notifications",
	}
}

// minimalCfg returns a basic enabled Nacm with no rules.
func minimalCfg() nacm.Nacm {
	return nacm.Nacm{EnableNacm: true}
}

// ─── TestEnforce_DecisionString ───────────────────────────────────────────────

// TestEnforce_DecisionString verifies that Decision.String() returns readable values.
func TestEnforce_DecisionString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "permit", nacm.Permit.String())
	assert.Equal(t, "deny", nacm.Deny.String())
	assert.Equal(t, "default-deny", nacm.DefaultDeny.String())
}

// ─── TestEnforce_NacmDisabled ─────────────────────────────────────────────────

// TestEnforce_NacmDisabled verifies that when NACM is disabled, all requests
// are permitted regardless of configured rules.
func TestEnforce_NacmDisabled(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: false,
		RuleLists: []nacm.RuleList{
			{
				Name:  "deny-everything",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "deny-all",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "*"},
						AccessOperations:  "*",
						Action:            nacm.ActionDeny,
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("alice", []string{"admin"}, "ietf-netconf", "get-config")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req), "NACM disabled must always permit")

	req2 := mkNotificationRequest("alice", []string{"admin"}, "netconf-config-change")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req2), "NACM disabled must always permit notifications")
}

// ─── TestEnforce_ProtocolOperation ────────────────────────────────────────────

// TestEnforce_ProtocolOperation_Permit verifies a rule that explicitly permits
// a specific protocol operation results in Permit.
func TestEnforce_ProtocolOperation_Permit(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "admin-rules",
				Group: []string{"admin"},
				Rules: []nacm.Rule{
					{
						Name:       "allow-get-config",
						ModuleName: "ietf-netconf",
						ProtocolOperation: &nacm.ProtocolOperationRule{
							RPCName: "get-config",
						},
						AccessOperations: "exec",
						Action:           nacm.ActionPermit,
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("alice", []string{"admin"}, "ietf-netconf", "get-config")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req))
}

// TestEnforce_ProtocolOperation_Deny verifies a rule that explicitly denies
// a specific protocol operation results in Deny.
func TestEnforce_ProtocolOperation_Deny(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "operator-rules",
				Group: []string{"operators"},
				Rules: []nacm.Rule{
					{
						Name:       "deny-edit-config",
						ModuleName: "ietf-netconf",
						ProtocolOperation: &nacm.ProtocolOperationRule{
							RPCName: "edit-config",
						},
						AccessOperations: "exec",
						Action:           nacm.ActionDeny,
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("charlie", []string{"operators"}, "ietf-netconf", "edit-config")
	assert.Equal(t, nacm.Deny, nacm.Enforce(cfg, req))
}

// ─── TestEnforce_Notification ─────────────────────────────────────────────────

// TestEnforce_Notification_Permit verifies a notification rule that permits
// results in Permit.
func TestEnforce_Notification_Permit(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "notif-rules",
				Group: []string{"admin"},
				Rules: []nacm.Rule{
					{
						Name:       "allow-config-change",
						ModuleName: "ietf-netconf-notifications",
						Notification: &nacm.NotificationRule{
							NotificationName: "netconf-config-change",
						},
						AccessOperations: "read",
						Action:           nacm.ActionPermit,
					},
				},
			},
		},
	}

	req := mkNotificationRequest("alice", []string{"admin"}, "netconf-config-change")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req))
}

// TestEnforce_Notification_Deny verifies a notification rule that denies
// results in Deny.
func TestEnforce_Notification_Deny(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "restricted-rules",
				Group: []string{"restricted"},
				Rules: []nacm.Rule{
					{
						Name:             "deny-all-notifs",
						ModuleName:       "*",
						Notification:     &nacm.NotificationRule{NotificationName: "*"},
						AccessOperations: "*",
						Action:           nacm.ActionDeny,
					},
				},
			},
		},
	}

	req := mkNotificationRequest("dave", []string{"restricted"}, "netconf-session-start")
	assert.Equal(t, nacm.Deny, nacm.Enforce(cfg, req))
}

// ─── TestEnforce_DefaultDeny ──────────────────────────────────────────────────

// TestEnforce_DefaultDeny verifies that when no rule matches, DefaultDeny
// is returned.
func TestEnforce_DefaultDeny(t *testing.T) {
	t.Parallel()
	// No rules at all.
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(minimalCfg(),
		mkProtocolOpRequest("alice", []string{"admin"}, "ietf-netconf", "get")))

	// Rules for a different group.
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "admin-rules",
				Group: []string{"admin"},
				Rules: []nacm.Rule{
					{
						Name:              "allow-get",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "exec",
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}
	// User is in "operators", not "admin" — no match.
	req := mkProtocolOpRequest("charlie", []string{"operators"}, "ietf-netconf", "get")
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(cfg, req))
}

// ─── TestEnforce_FirstMatchWins ───────────────────────────────────────────────

// TestEnforce_FirstMatchWins verifies that the first matching rule in a
// rule-list determines the decision, even when subsequent rules would disagree.
func TestEnforce_FirstMatchWins(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "mixed-rules",
				Group: []string{}, // applies to all
				Rules: []nacm.Rule{
					{
						Name: "deny-first",
						ProtocolOperation: &nacm.ProtocolOperationRule{
							RPCName: "get-config",
						},
						AccessOperations: "exec",
						Action:           nacm.ActionDeny, // first: deny
					},
					{
						Name: "permit-second",
						ProtocolOperation: &nacm.ProtocolOperationRule{
							RPCName: "get-config",
						},
						AccessOperations: "exec",
						Action:           nacm.ActionPermit, // second: permit — must not be reached
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("alice", []string{"admin"}, "ietf-netconf", "get-config")
	assert.Equal(t, nacm.Deny, nacm.Enforce(cfg, req), "first matching rule (deny) must win over second (permit)")
}

// TestEnforce_FirstMatchWins_AcrossLists verifies that earlier rule-lists
// take precedence over later ones.
func TestEnforce_FirstMatchWins_AcrossLists(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "first-list",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "permit-get",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "exec",
						Action:            nacm.ActionPermit,
					},
				},
			},
			{
				Name:  "second-list",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "deny-get",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "exec",
						Action:            nacm.ActionDeny,
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("alice", []string{"admin"}, "ietf-netconf", "get")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req), "first list's permit must win over second list's deny")
}

// ─── TestEnforce_Wildcard ─────────────────────────────────────────────────────

// TestEnforce_WildcardRPC verifies that a rule with RPCName="*" matches any
// protocol operation.
func TestEnforce_WildcardRPC(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "allow-all-rpcs",
				Group: []string{"admin"},
				Rules: []nacm.Rule{
					{
						Name:              "wildcard-rpc",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "*"},
						AccessOperations:  "exec",
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	for _, rpc := range []string{"get", "get-config", "edit-config", "lock", "commit", "some-custom-rpc"} {
		req := mkProtocolOpRequest("alice", []string{"admin"}, "ietf-netconf", rpc)
		assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req), "wildcard RPC should match %q", rpc)
	}
}

// TestEnforce_WildcardModule verifies that a rule with ModuleName="*" matches
// any module.
func TestEnforce_WildcardModule(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "wildcard-module-rules",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "wildcard-module",
						ModuleName:        "*",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "exec",
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	for _, mod := range []string{"ietf-netconf", "some-vendor-module", "anything"} {
		req := mkProtocolOpRequest("alice", []string{}, mod, "get")
		assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req), "wildcard module should match %q", mod)
	}
}

// TestEnforce_WildcardAccessOperations verifies that AccessOperations="*"
// matches any operation type.
func TestEnforce_WildcardAccessOperations(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "wildcard-access",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "wildcard-ops",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "*"},
						AccessOperations:  "*",
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("alice", []string{}, "ietf-netconf", "get-config")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req))
}

// ─── TestEnforce_GroupFilter ──────────────────────────────────────────────────

// TestEnforce_GroupFilter verifies that a rule-list with a specific Group
// list only applies when the user is a member of one of those groups.
func TestEnforce_GroupFilter(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "admin-only",
				Group: []string{"admin"},
				Rules: []nacm.Rule{
					{
						Name:              "admin-get",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "exec",
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	// User in "user" group (not "admin") — no match.
	reqNoMatch := mkProtocolOpRequest("dave", []string{"user"}, "ietf-netconf", "get")
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(cfg, reqNoMatch), "non-member should not match")

	// User in "admin" group — matches.
	reqMatch := mkProtocolOpRequest("alice", []string{"admin"}, "ietf-netconf", "get")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, reqMatch), "admin member should match")

	// User in multiple groups, one of which is "admin" — matches.
	reqMultiGroup := mkProtocolOpRequest("bob", []string{"user", "admin"}, "ietf-netconf", "get")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, reqMultiGroup), "user in multiple groups should match on admin")
}

// TestEnforce_EmptyGroupList verifies that a rule-list with an empty Group
// slice applies to all users regardless of group membership.
func TestEnforce_EmptyGroupList(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "everyone",
				Group: []string{}, // applies to all
				Rules: []nacm.Rule{
					{
						Name:              "permit-get",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "exec",
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	for _, groups := range [][]string{
		{"admin"},
		{"user"},
		{"some-random-group"},
		{}, // user with no group memberships
	} {
		req := mkProtocolOpRequest("anyone", groups, "ietf-netconf", "get")
		assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req),
			"empty group list should apply to all users (groups=%v)", groups)
	}
}

// ─── TestEnforce_RuleTypeMismatch ─────────────────────────────────────────────

// TestEnforce_RuleTypeMismatch verifies that a protocol-operation rule does not
// match a notification request, and vice versa.
func TestEnforce_RuleTypeMismatch(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "proto-op-rules",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "permit-rpc",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "*"},
						AccessOperations:  "*",
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	// Notification request should not match a protocol-operation rule.
	req := mkNotificationRequest("alice", []string{"admin"}, "netconf-config-change")
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(cfg, req),
		"notification request must not match protocol-operation rule")
}

// ─── TestEnforce_ModuleMismatch ───────────────────────────────────────────────

// TestEnforce_ModuleMismatch verifies that a rule with a specific module name
// does not match requests from a different module.
func TestEnforce_ModuleMismatch(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "ietf-netconf-only",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "permit-get",
						ModuleName:        "ietf-netconf",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "exec",
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	// Request from a different module should not match.
	req := mkProtocolOpRequest("alice", []string{}, "ietf-netconf-monitoring", "get")
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(cfg, req),
		"rule for ietf-netconf must not match ietf-netconf-monitoring")
}

// ─── TestEnforce_AccessOperations_SpaceSeparated ──────────────────────────────

// TestEnforce_AccessOperations_SpaceSeparated verifies that space-separated
// access-operations values work correctly.
func TestEnforce_AccessOperations_SpaceSeparated(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "multi-access",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "read-exec",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "read exec", // space-separated, includes exec
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("alice", []string{}, "ietf-netconf", "get")
	assert.Equal(t, nacm.Permit, nacm.Enforce(cfg, req),
		"exec in space-separated access-operations should match")
}

// TestEnforce_AccessOperations_NoExec verifies that a rule with only "read"
// access does not match a protocol-operation request (which requires "exec").
func TestEnforce_AccessOperations_NoExec(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "read-only-rules",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "read-only",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "get"},
						AccessOperations:  "read", // read only — not exec
						Action:            nacm.ActionPermit,
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("alice", []string{}, "ietf-netconf", "get")
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(cfg, req),
		"read-only access-operations must not match protocol-operation exec request")
}

// ─── TestDecisionString_Unknown ───────────────────────────────────────────────

// TestDecisionString_Unknown verifies that an out-of-range Decision value
// returns "unknown" from String().
func TestDecisionString_Unknown(t *testing.T) {
	t.Parallel()
	d := nacm.Decision(99)
	assert.Equal(t, "unknown", d.String())
}

// ─── TestEnforce_UnknownOperationType ─────────────────────────────────────────

// TestEnforce_UnknownOperationType verifies that a request with an
// OperationType not equal to OpProtocolOperation or OpNotification causes
// ruleTypeMatches to return false, so no rule matches and DefaultDeny is
// returned.
func TestEnforce_UnknownOperationType(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "catch-all",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:              "permit-proto",
						ProtocolOperation: &nacm.ProtocolOperationRule{RPCName: "*"},
						AccessOperations:  "*",
						Action:            nacm.ActionPermit,
					},
					{
						Name:             "permit-notif",
						Notification:     &nacm.NotificationRule{NotificationName: "*"},
						AccessOperations: "*",
						Action:           nacm.ActionPermit,
					},
				},
			},
		},
	}

	req := nacm.Request{
		User:          "alice",
		Groups:        []string{"admin"},
		OperationType: nacm.OperationType(99),
		OperationName: "something",
		ModuleName:    "some-module",
	}
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(cfg, req),
		"unknown OperationType must not match any rule")
}

// ─── TestEnforce_ProtocolOpAgainstNotificationRule ────────────────────────────

// TestEnforce_ProtocolOpAgainstNotificationRule verifies that a protocol
// operation request does not match a notification-only rule (ProtocolOperation
// is nil), exercising the nil-check branch in ruleTypeMatches.
func TestEnforce_ProtocolOpAgainstNotificationRule(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "notif-only-rules",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:             "permit-notif",
						Notification:     &nacm.NotificationRule{NotificationName: "*"},
						AccessOperations: "*",
						Action:           nacm.ActionPermit,
					},
				},
			},
		},
	}

	req := mkProtocolOpRequest("alice", []string{"admin"}, "ietf-netconf", "get")
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(cfg, req),
		"protocol-operation request must not match notification-only rule")
}

// ─── TestEnforce_AccessOperations_UnknownOpType ───────────────────────────────

// TestEnforce_AccessOperations_UnknownOpType verifies that
// accessOperationMatches returns false for an unknown OperationType when
// AccessOperations is a non-wildcard string, exercising the default branch.
func TestEnforce_AccessOperations_UnknownOpType(t *testing.T) {
	t.Parallel()
	cfg := nacm.Nacm{
		EnableNacm: true,
		RuleLists: []nacm.RuleList{
			{
				Name:  "catch-all",
				Group: []string{},
				Rules: []nacm.Rule{
					{
						Name:             "permit-notif",
						Notification:     &nacm.NotificationRule{NotificationName: "*"},
						AccessOperations: "exec read",
						Action:           nacm.ActionPermit,
					},
				},
			},
		},
	}

	req := nacm.Request{
		User:          "alice",
		Groups:        []string{"admin"},
		OperationType: nacm.OperationType(99),
		OperationName: "something",
		ModuleName:    "some-module",
	}
	assert.Equal(t, nacm.DefaultDeny, nacm.Enforce(cfg, req),
		"unknown OperationType with non-wildcard access-operations must not match")
}
