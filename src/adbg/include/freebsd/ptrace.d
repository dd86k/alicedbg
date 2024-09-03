/// ptrace(3) bindings for FreeBSD.
///
/// Sources:
/// - freebsd-src/sys/sys/ptrace.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.freebsd.ptrace;

version (FreeBSD):

import core.sys.posix.unistd : pid_t;

// Defined for OpenBSD in core.sys.posix.sys.types, but not NetBSD and FreeBSD.
// FreeBSD, if I looked at the source correctly, should be ubyte*.
// But Linux have its ptrace addr type set as void*, so let's do just that,
// it's just a pointer definition.
alias caddr_t = void*;

extern (C):

enum {
	PT_TRACE_ME	= 0,	/* child declares it's being traced */
	PT_READ_I	= 1,	/* read word in child's I space */
	PT_READ_D	= 2,	/* read word in child's D space */
	/* was	PT_READ_U	3	 * read word in child's user structure */
	PT_WRITE_I	= 4,	/* write word in child's I space */
	PT_WRITE_D	= 5,	/* write word in child's D space */
	/* was	PT_WRITE_U	6	 * write word in child's user structure */
	PT_CONTINUE	= 7,	/* continue the child */
	PT_KILL		= 8,	/* kill the child process */
	PT_STEP		= 9,	/* single step the child */
	PT_ATTACH	= 10,	/* trace some running process */
	PT_DETACH	= 11,	/* stop tracing a process */
	PT_IO		= 12,	/* do I/O to/from stopped process. */
	PT_LWPINFO	= 13,	/* Info about the LWP that stopped. */
	PT_GETNUMLWPS	= 14,	/* get total number of threads */
	PT_GETLWPLIST	= 15,	/* get thread list */
	PT_CLEARSTEP	= 16,	/* turn off single step */
	PT_SETSTEP	= 17,	/* turn on single step */
	PT_SUSPEND	= 18,	/* suspend a thread */
	PT_RESUME	= 19,	/* resume a thread */

	PT_TO_SCE	= 20,
	PT_TO_SCX	= 21,
	PT_SYSCALL	= 22,

	PT_FOLLOW_FORK	= 23,
	PT_LWP_EVENTS	= 24,	/* report LWP birth and exit */

	PT_GET_EVENT_MASK = 25,	/* get mask of optional events */
	PT_SET_EVENT_MASK = 26,	/* set mask of optional events */

	PT_GET_SC_ARGS	= 27,	/* fetch syscall args */
	PT_GET_SC_RET	= 28,	/* fetch syscall results */

	PT_COREDUMP	= 29,	/* create a coredump */

	PT_GETREGS      = 33,	/* get general-purpose registers */
	PT_SETREGS      = 34,	/* set general-purpose registers */
	PT_GETFPREGS    = 35,	/* get floating-point registers */
	PT_SETFPREGS    = 36,	/* set floating-point registers */
	PT_GETDBREGS    = 37,	/* get debugging registers */
	PT_SETDBREGS    = 38,	/* set debugging registers */

	PT_VM_TIMESTAMP	= 40,	/* Get VM version (timestamp) */
	PT_VM_ENTRY	= 41,	/* Get VM map (entry) */
	PT_GETREGSET	= 42,	/* Get a target register set */
	PT_SETREGSET	= 43,	/* Set a target register set */
	PT_SC_REMOTE	= 44,	/* Execute a syscall */

	PT_FIRSTMACH    = 64,	/* for machine-specific requests */
}

// Linux aliases
alias PT_TRACEME 	= PT_TRACE_ME;
alias PT_CONT 	= PT_CONTINUE;
alias PT_SINGLESTEP 	= PT_STEP;

/* Events used with PT_GET_EVENT_MASK and PT_SET_EVENT_MASK */
enum PTRACE_EXEC	= 0x0001;
enum PTRACE_SCE	= 0x0002;
enum PTRACE_SCX	= 0x0004;
enum PTRACE_SYSCALL	= (PTRACE_SCE | PTRACE_SCX);
enum PTRACE_FORK	= 0x0008;
enum PTRACE_LWP	= 0x0010;
enum PTRACE_VFORK	= 0x0020;

enum PTRACE_DEFAULT	= PTRACE_EXEC;

struct ptrace_io_desc {
	int	piod_op;	/* I/O operation */
	void	*piod_offs;	/* child offset */
	void	*piod_addr;	/* parent offset */
	size_t	piod_len;	/* request length */
}

/*
 * Operations in piod_op.
 */
enum PIOD_READ_D	= 1;	/* Read from D space */
enum PIOD_WRITE_D	= 2;	/* Write to D space */
enum PIOD_READ_I	= 3;	/* Read from I space */
enum PIOD_WRITE_I	= 4;	/* Write to I space */

/* Argument structure for PT_LWPINFO. */
/+
struct ptrace_lwpinfo {
	lwpid_t	pl_lwpid;	/* LWP described. */
	int	pl_event;	/* Event that stopped the LWP. */
PL_EVENT_NONE	0
PL_EVENT_SIGNAL	1
	int	pl_flags;	/* LWP flags. */
PL_FLAG_SA	0x01	/* M:N thread */
PL_FLAG_BOUND	0x02	/* M:N bound thread */
PL_FLAG_SCE	0x04	/* syscall enter point */
PL_FLAG_SCX	0x08	/* syscall leave point */
PL_FLAG_EXEC	0x10	/* exec(2) succeeded */
PL_FLAG_SI	0x20	/* siginfo is valid */
PL_FLAG_FORKED	0x40	/* new child */
PL_FLAG_CHILD	0x80	/* I am from child */
PL_FLAG_BORN	0x100	/* new LWP */
PL_FLAG_EXITED	0x200	/* exiting LWP */
PL_FLAG_VFORKED	0x400	/* new child via vfork */
PL_FLAG_VFORK_DONE 0x800 /* vfork parent has resumed */
	sigset_t	pl_sigmask;	/* LWP signal mask */
	sigset_t	pl_siglist;	/* LWP pending signal */
	struct __siginfo pl_siginfo;	/* siginfo for signal */
	char		pl_tdname[MAXCOMLEN + 1]; /* LWP name */
	pid_t		pl_child_pid;	/* New child pid */
	u_int		pl_syscall_code;
	u_int		pl_syscall_narg;
};

#if defined(_WANT_LWPINFO32) || (defined(_KERNEL) && defined(__LP64__))
struct ptrace_lwpinfo32 {
	lwpid_t	pl_lwpid;	/* LWP described. */
	int	pl_event;	/* Event that stopped the LWP. */
	int	pl_flags;	/* LWP flags. */
	sigset_t	pl_sigmask;	/* LWP signal mask */
	sigset_t	pl_siglist;	/* LWP pending signal */
	struct __siginfo32 pl_siginfo;	/* siginfo for signal */
	char		pl_tdname[MAXCOMLEN + 1]; /* LWP name. */
	pid_t		pl_child_pid;	/* New child pid */
	u_int		pl_syscall_code;
	u_int		pl_syscall_narg;
};

/* Argument structure for PT_GET_SC_RET. */
struct ptrace_sc_ret {
	syscallarg_t	sr_retval[2];	/* Only valid if sr_error == 0. */
	int		sr_error;
};

/* Argument structure for PT_VM_ENTRY. */
struct ptrace_vm_entry {
	int		pve_entry;	/* Entry number used for iteration. */
	int		pve_timestamp;	/* Generation number of VM map. */
	u_long		pve_start;	/* Start VA of range. */
	u_long		pve_end;	/* End VA of range (incl). */
	u_long		pve_offset;	/* Offset in backing object. */
	u_int		pve_prot;	/* Protection of memory range. */
	u_int		pve_pathlen;	/* Size of path. */
	long		pve_fileid;	/* File ID. */
	uint32_t	pve_fsid;	/* File system ID. */
	char		*pve_path;	/* Path name of object. */
};

/* Argument structure for PT_COREDUMP */
struct ptrace_coredump {
	int		pc_fd;		/* File descriptor to write dump to. */
	uint32_t	pc_flags;	/* Flags PC_* */
	off_t		pc_limit;	/* Maximum size of the coredump,
					   0 for no limit. */
};

/* Flags for PT_COREDUMP pc_flags */
PC_COMPRESS	0x00000001	/* Allow compression */
PC_ALL		0x00000002	/* Include non-dumpable entries */

struct ptrace_sc_remote {
	struct ptrace_sc_ret pscr_ret;
	u_int	pscr_syscall;
	u_int	pscr_nargs;
	syscallarg_t	*pscr_args;
};

struct thr_coredump_req {
	struct vnode	*tc_vp;		/* vnode to write coredump to. */
	off_t		tc_limit;	/* max coredump file size. */
	int		tc_flags;	/* user flags */
	int		tc_error;	/* request result */
};

struct thr_syscall_req {
	struct ptrace_sc_ret ts_ret;
	u_int	ts_nargs;
	struct syscall_args ts_sa;
};

int	ptrace_set_pc(struct thread *_td, unsigned long _addr);
int	ptrace_single_step(struct thread *_td);
int	ptrace_clear_single_step(struct thread *_td);

#ifdef __HAVE_PTRACE_MACHDEP
int	cpu_ptrace(struct thread *_td, int _req, void *_addr, int _data);
#endif

/*
 * These are prototypes for functions that implement some of the
 * debugging functionality exported by procfs / linprocfs and by the
 * ptrace(2) syscall.  They used to be part of procfs, but they don't
 * really belong there.
 */
struct reg;
struct fpreg;
struct dbreg;
struct uio;
int	proc_read_regs(struct thread *_td, struct reg *_reg);
int	proc_write_regs(struct thread *_td, struct reg *_reg);
int	proc_read_fpregs(struct thread *_td, struct fpreg *_fpreg);
int	proc_write_fpregs(struct thread *_td, struct fpreg *_fpreg);
int	proc_read_dbregs(struct thread *_td, struct dbreg *_dbreg);
int	proc_write_dbregs(struct thread *_td, struct dbreg *_dbreg);
int	proc_sstep(struct thread *_td);
int	proc_rwmem(struct proc *_p, struct uio *_uio);
ssize_t	proc_readmem(struct thread *_td, struct proc *_p, vm_offset_t _va,
	    void *_buf, size_t _len);
ssize_t	proc_writemem(struct thread *_td, struct proc *_p, vm_offset_t _va,
	    void *_buf, size_t _len);

#ifdef COMPAT_FREEBSD32
struct reg32;
struct fpreg32;
struct dbreg32;
int	proc_read_regs32(struct thread *_td, struct reg32 *_reg32);
int	proc_write_regs32(struct thread *_td, struct reg32 *_reg32);
int	proc_read_fpregs32(struct thread *_td, struct fpreg32 *_fpreg32);
int	proc_write_fpregs32(struct thread *_td, struct fpreg32 *_fpreg32);
int	proc_read_dbregs32(struct thread *_td, struct dbreg32 *_dbreg32);
int	proc_write_dbregs32(struct thread *_td, struct dbreg32 *_dbreg32);

void	ptrace_unsuspend(struct proc *p);
#endif
+/

int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);