package hscontrol

import (
	"net/netip"
	"testing"

	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
)

func Test_requestTagsChanged(t *testing.T) {
	tests := []struct {
		name string
		old  []string
		new  []string
		want bool
	}{
		{"nil vs nil", nil, nil, false},
		{"nil vs empty", nil, []string{}, false},
		{"same", []string{"tag:a", "tag:b"}, []string{"tag:a", "tag:b"}, false},
		{"same, different order", []string{"tag:a", "tag:b"}, []string{"tag:b", "tag:a"}, false},
		{"added", []string{"tag:a"}, []string{"tag:a", "tag:b"}, true},
		{"removed", []string{"tag:a", "tag:b"}, []string{"tag:a"}, true},
		{"replaced", []string{"tag:a"}, []string{"tag:b"}, true},
		{"cleared", []string{"tag:a"}, nil, true},
		{"duplicates collapse", []string{"tag:a", "tag:a"}, []string{"tag:a"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestTagsChanged(tt.old, tt.new); got != tt.want {
				t.Errorf("requestTagsChanged(%v, %v) = %v, want %v", tt.old, tt.new, got, tt.want)
			}
		})
	}
}

// Reloading the machine cache is the single point every machine lifecycle
// change goes through (register, expire, delete, tag changes, user changes),
// so it must rebuild the ACL filter without any caller asking for it.
func (s *Suite) TestLoadPrefetchMachinesRebuildsACLRules(c *check.C) {
	user, err := app.CreateUser("gating-user")
	c.Assert(err, check.IsNil)
	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	app.aclPolicy = &ACLPolicy{
		TagOwners: TagOwners{"tag:gating": []string{"gating-user"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"tag:gating"},
				Destinations: []string{"*:*"},
			},
		},
	}
	app.aclRules = nil

	machine := Machine{
		MachineKey:     "gating-mkey",
		NodeKey:        "gating-nkey",
		DiscoKey:       "gating-dkey",
		Hostname:       "gating-machine",
		IPAddresses:    MachineAddresses{netip.MustParseAddr("100.64.0.77")},
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo: HostInfo(tailcfg.Hostinfo{
			Hostname:    "gating-machine",
			RequestTags: []string{"tag:gating"},
		}),
	}
	c.Assert(app.db.Save(&machine).Error, check.IsNil)

	// Nothing rebuilt yet: the rules do not know about the machine.
	c.Assert(rulesContainSrc(app.aclRules, "100.64.0.77/32"), check.Equals, false)

	c.Assert(app.LoadPrefetchMachinesFromDB(), check.IsNil)
	c.Assert(rulesContainSrc(app.aclRules, "100.64.0.77/32"), check.Equals, true)

	// Deleting the machine reloads the cache and must drop it from the rules.
	c.Assert(app.DeleteMachine(&machine), check.IsNil)
	c.Assert(rulesContainSrc(app.aclRules, "100.64.0.77/32"), check.Equals, false)
}

// Reloading the cache with no policy loaded must not fail: at startup the
// machine cache is populated before the policy is.
func (s *Suite) TestLoadPrefetchMachinesWithoutPolicy(c *check.C) {
	app.aclPolicy = nil
	app.aclRules = nil
	c.Assert(app.LoadPrefetchMachinesFromDB(), check.IsNil)
	c.Assert(app.aclRules, check.IsNil)
}

func rulesContainSrc(rules []tailcfg.FilterRule, src string) bool {
	for _, rule := range rules {
		for _, s := range rule.SrcIPs {
			if s == src {
				return true
			}
		}
	}
	return false
}
