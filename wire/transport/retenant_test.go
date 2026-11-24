package transport

import "testing"

// TestChangesTenant: the moves that need retenant on their source profile — a perTenant move to another tenant, and
// every move between a shared and a perTenant profile, either way, derived profiles alike — and the ones that do not:
// two shared profiles, and one tenant between two perTenant profiles.
func TestChangesTenant(t *testing.T) {
	const (
		shared  = TenancyShared
		wrapped = TenancyPerTenantWrapped
		derived = TenancyPerTenantDerived
	)
	for _, c := range []struct {
		name     string
		from     Tenancy
		tenant   string
		to       Tenancy
		toTenant string
		changes  bool
	}{
		{"shared to shared", shared, "", shared, "", false},
		{"wrapped, same tenant", wrapped, "t_a", wrapped, "t_a", false},
		{"derived, same tenant", derived, "t_a", derived, "t_a", false},
		{"wrapped to derived, same tenant", wrapped, "t_a", derived, "t_a", false},
		{"derived to wrapped, same tenant", derived, "t_a", wrapped, "t_a", false},
		{"wrapped, another tenant", wrapped, "t_a", wrapped, "t_b", true},
		{"derived, another tenant", derived, "t_a", derived, "t_b", true},
		{"wrapped to derived, another tenant", wrapped, "t_a", derived, "t_b", true},
		{"tenant ids differing in case only", wrapped, "t_a", wrapped, "T_A", true},
		{"shared to wrapped", shared, "", wrapped, "t_a", true},
		{"shared to derived", shared, "", derived, "t_a", true},
		{"wrapped to shared", wrapped, "t_a", shared, "", true},
		{"derived to shared", derived, "t_a", shared, "", true},
		{"an unknown source tenancy", "", "", shared, "", true},
		{"an unknown target tenancy", shared, "", "sealed", "", true},
	} {
		if got := ChangesTenant(c.from, c.tenant, c.to, c.toTenant); got != c.changes {
			t.Errorf("%s: ChangesTenant = %v, want %v", c.name, got, c.changes)
		}
	}
}
