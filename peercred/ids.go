package peercred

import (
	"os"
	"strconv"
	"strings"
)

// DefaultOverflowID is the kernel's default overflow uid and gid (/proc/sys/kernel/overflowuid, overflowgid):
// 65534, also "nobody" on most systems.
const DefaultOverflowID = 65534

// OverflowIDs are the ids the Linux kernel reports for an id that has no mapping in the reader's user namespace.
// Every process whose real id is unmapped is seen with them, so a check that names one names all of those
// processes at once. Read from /proc where it exists; DefaultOverflowID elsewhere.
func OverflowIDs() (uid, gid uint32) {
	return readID("/proc/sys/kernel/overflowuid"), readID("/proc/sys/kernel/overflowgid")
}

func readID(path string) uint32 {
	b, err := os.ReadFile(path)
	if err != nil {
		return DefaultOverflowID
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil {
		return DefaultOverflowID
	}
	return uint32(n)
}

// RefusedID says why id does not name one account a peer credential can be trusted to stand for, or "" when it
// does. isUID picks the overflow uid or gid. cipheron's server refuses such an id in a caller entry and as the
// socket's group (the server's configuration), and its client refuses it as the server's uid (WithServerUID,
// CIPHERON_SERVER_UID): one list for both ends.
//
//   - 0: root. cipheron does not serve root by configuration, and a client that pinned its server to root would
//     accept any root process as cipheron — the pin would exclude nothing a root attacker could not be.
//   - the kernel's overflow id (and 65534, "nobody", whatever the kernel's is): every process whose id has no
//     mapping in the reader's user namespace is seen with it, so it names all of them at once.
//   - 4294967294 and 4294967295: (uid_t)-2, NFS's anonymous id, and (uid_t)-1, which is no id at all.
func RefusedID(id uint32, isUID bool) string {
	ou, og := OverflowIDs()
	overflow := og
	if isUID {
		overflow = ou
	}
	switch {
	case id == 0:
		return "it is root (id 0), which names no one in particular: every root process is it"
	case id == overflow || id == DefaultOverflowID:
		return "it is the kernel's overflow id (\"nobody\"), which every process with an unmapped id is seen with"
	case id >= 4294967294:
		return "it is (uid_t)-2 or (uid_t)-1, not an id that names one account"
	}
	return ""
}
