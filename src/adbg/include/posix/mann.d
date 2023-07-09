/**
 * Mapping for sys/mman.h.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.include.posix.mann;

version (Posix):

public import core.sys.posix.stdlib : ssize_t, off_t;

extern (C):

enum MAP_SHARED	= 0x01;		/// Share changes
enum MAP_PRIVATE	= 0x02;		/// Changes are private
enum MAP_SHARED_VALIDATE = 0x03;	/// share + validate extension flags
enum MAP_TYPE	= 0x0f;		/// Mask for type of mapping
enum MAP_FIXED	= 0x10;		/// Interpret addr exactly
enum MAP_ANONYMOUS	= 0x20;		/// don't use a file
// Linux specifics
enum MAP_GROWSDOWN	= 0x01000;		/// stack-like segment
enum MAP_DENYWRITE	= 0x02000;		/// ETXTBSY
enum MAP_EXECUTABLE	= 0x04000;		/// mark it as an executable
enum MAP_LOCKED	= 0x08000;		/// lock the mapping
enum MAP_NORESERVE	= 0x10000;		/// don't check for reservations
enum MAP_POPULATE	= 0x20000;		/// populate (prefault) pagetables
enum MAP_NONBLOCK	= 0x40000;		/// do not block on IO
enum MAP_STACK	= 0x80000;		/// give out an address that is best suited for process/thread stacks
enum MAP_HUGETLB	= 0x100000;	/// create a huge page mapping
enum MAP_FIXED_NOREPLACE	= 0x200000;	/// MAP_FIXED which doesn't unmap underlying mapping

enum MAP_FAILED = cast(void*)-1;	/// mmap returns MAP_FAILED when it failed to allocate

enum PROT_READ	= 0x1;		/// page can be read
enum PROT_WRITE	= 0x2;		/// page can be written
enum PROT_EXEC	= 0x4;		/// page can be executed
enum PROT_SEM	= 0x8;		/// page may be used for atomic ops
enum PROT_NONE	= 0x0;		/// page can not be accessed
enum PROT_GROWSDOWN	= 0x01000000;	/// mprotect flag: extend change to start of growsdown vma
enum PROT_GROWSUP	= 0x02000000;	/// mprotect flag: extend change to end of growsup vma

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);
