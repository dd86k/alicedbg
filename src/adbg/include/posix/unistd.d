/// Up to date Posix universal standard defitions (unistd.h) and other utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.posix.unistd;

version (Posix):

public import core.sys.posix.unistd;

extern (C):

// Missing XOpen (XSI) definitions for Musl
version (CRuntime_Musl) {
	public import core.sys.posix.stdlib : ssize_t, off_t;
	public ssize_t pread(int, void *, size_t, off_t);
	public ssize_t pwrite(int, const(void)*, size_t, off_t);
}

// Only Linux has clone(2), BSDs still have fork(2)
version (linux):

// Cloning flags
enum CSIGNAL	= 0x000000ff;	/// signal mask to be sent at exit
enum CLONE_VM	= 0x00000100;	/// set if VM shared between processes
enum CLONE_FS	= 0x00000200;	/// set if fs info shared between processes
enum CLONE_FILES	= 0x00000400;	/// set if open files shared between processes
enum CLONE_SIGHAND	= 0x00000800;	/// set if signal handlers and blocked signals shared
enum CLONE_PTRACE	= 0x00002000;	/// set if we want to let tracing continue on the child too
enum CLONE_VFORK	= 0x00004000;	/// set if the parent wants the child to wake it up on mm_release
enum CLONE_PARENT	= 0x00008000;	/// set if we want to have the same parent as the cloner
enum CLONE_THREAD	= 0x00010000;	/// Same thread group?
enum CLONE_NEWNS	= 0x00020000;	/// New mount namespace group
enum CLONE_SYSVSEM	= 0x00040000;	/// share system V SEM_UNDO semantics
enum CLONE_SETTLS	= 0x00080000;	/// create a new TLS for the child
enum CLONE_PARENT_SETTID	= 0x00100000;	/// set the TID in the parent
enum CLONE_CHILD_CLEARTID	= 0x00200000;	/// clear the TID in the child
enum CLONE_DETACHED	= 0x00400000;	/// Unused, ignored
enum CLONE_UNTRACED	= 0x00800000;	/// set if the tracing process can't force CLONE_PTRACE on this clone
enum CLONE_CHILD_SETTID	= 0x01000000;	/// set the TID in the child
enum CLONE_NEWCGROUP	= 0x02000000;	/// New cgroup namespace
enum CLONE_NEWUTS	= 0x04000000;	/// New utsname namespace
enum CLONE_NEWIPC	= 0x08000000;	/// New ipc namespace
enum CLONE_NEWUSER	= 0x10000000;	/// New user namespace
enum CLONE_NEWPID	= 0x20000000;	/// New pid namespace
enum CLONE_NEWNET	= 0x40000000;	/// New network namespace
enum CLONE_IO	= 0x80000000;	/// Clone io context

// shed.h
int clone(int function(void *), void *stack, int flags, void *arg, ...
	/* pid_t *parent_tid, void *tls, pid_t *child_tid */ );