# Native metadata ABI setup scope

A POSIX J2 fresh native read lane now retains one private Darwin ABI binding table in its existing ExitStack. This avoids rebuilding ctypes library handles and configuring xattr/ACL signatures for every observation. Symbol groups are lazy: Linux and Windows observations do not bind Darwin APIs. Unscoped callers retain per-call setup.

Each scope has a ContextVar token and a fresh holder. Nested and exceptional exits deactivate that holder and restore the exact previous scope. Reuse is restricted to the owning thread and asynchronous task while the scope is active; copied foreign contexts and copies retained after scope exit use fresh bindings. Changing the ctypes.CDLL factory within the owning active scope refuses reuse. The holder retains only library/function bindings, never observed filesystem state.

Every platform/machine/Python adapter check, native syscall, argument, buffer retry, errno branch, metadata observation, before/after fstat, lock, history, and topology check remains live. No journal, custody, permissions, historical authority, or canonical backend contract changes.

Bounded current native J2 fixture measurements on Mac/Python 3.13 used 11 and 19 publication slots. Under cProfile, observed publication times fell from 10.600/17.737 seconds to 7.585/11.918 seconds. Selected observation, adapter-gate, topology, history, replay and canonical counts matched exactly. Golden syscall traces cover xattr/ACL success, absence, syscall errors, inventory/value drift and ACL serialization errors; scope tests cover reset, factory drift, thread/task isolation and reader-entry/body errors.

These are single profiler samples of existing synthetic-source native fixtures, not canonical full-profile/public acceptance or an SLA. Full topology scans still repeat before and after every active slot. The separate historical 13,796.494-second full-profile receipt remains a performance limitation until the canonical full operation is measured again.
