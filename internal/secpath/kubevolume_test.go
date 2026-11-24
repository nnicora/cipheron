//go:build linux || darwin

package secpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kubeVolume lays out a Kubernetes volume as the kubelet's AtomicWriter writes it — the file in a timestamped
// directory (0755), "..data" linking to it, the file linked "..data/<name>" from the root — under a root of mode.
func kubeVolume(t *testing.T, root string, mode os.FileMode) string {
	t.Helper()
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ts := filepath.Join(root, "..2026_11_10_00_00_00.1")
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ts, "k.pub"), []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(ts), filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/k.pub", filepath.Join(root, "k.pub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, mode); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "k.pub")
}

// TestKubernetesVolumeRoots (review finding 2; the reviewer's repro): the rule is NOT relaxed for Kubernetes — the
// charts mount every ConfigMap through a projected volume instead.
//   - A plain configMap volume is a disk-backed emptyDir wrapper: its root is 0777, not sticky (setgid with an
//     fsGroup). A directory others can write without the sticky bit is refused on the way to a file, so a file in
//     such a volume is refused.
//   - A projected (or secret) volume is a tmpfs: its root is 1777 (setgid too with an fsGroup), sticky, accepted above
//     the file; the file itself is read from the root-owned 0755 timestamped directory.
func TestKubernetesVolumeRoots(t *testing.T) {
	base := t.TempDir()

	cm := kubeVolume(t, filepath.Join(base, "configmap"), 0o777|os.ModeSetgid)
	if _, err := ReadFile(cm, "caller request key", Public, 64); err == nil ||
		!strings.Contains(err.Error(), "without the sticky bit") {
		t.Fatalf("a file in a plain configMap volume (root 2777): %v, want refused", err)
	}
	if err := CheckDirectory(filepath.Dir(cm), false); err == nil {
		t.Fatal("a plain configMap volume's root (2777) passed as a directory")
	}

	pv := kubeVolume(t, filepath.Join(base, "projected"), 0o777|os.ModeSticky|os.ModeSetgid)
	if b, err := ReadFile(pv, "caller request key", Public, 64); err != nil || string(b) != "x" {
		t.Fatalf("a file in a projected volume (root 3777): %q %v", b, err)
	}
	if err := CheckDirectory(filepath.Dir(pv), false); err != nil {
		t.Fatalf("a projected volume's root (3777) as a directory above: %v", err)
	}
	// Strict, the root itself is refused: a sticky directory others can write still lets them add files. Who needs
	// a strict directory reads from the timestamped one "..data" names (internal/client, the pins).
	if err := CheckDirectory(filepath.Dir(pv), true); err == nil {
		t.Fatal("a projected volume's root passed as a strict leaf")
	}
	if err := CheckDirectory(filepath.Join(filepath.Dir(pv), "..2026_11_10_00_00_00.1"), true); err != nil {
		t.Fatalf("the timestamped directory as a strict leaf: %v", err)
	}
}
