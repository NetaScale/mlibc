#include <bits/ensure.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/thread-entry.hpp>

#include "../../kernel/posix/sys.h"
#include "abi-bits/errno.h"

namespace mlibc {

void
sys_libc_log(const char *message)
{
	syscall1(kPXSysDebug, (uintptr_t)message);
}

void
sys_libc_panic()
{
	mlibc::infoLogger() << "\e[31mmlibc: panic!" << frg::endlog;
	asm volatile("syscall" : : "a"(12), "D"(1) : "rcx", "r11", "rdx");
}

int
sys_tcb_set(void *pointer)
{
	return syscall1(kPXSysSetFSBase, (uintptr_t)pointer);
}

int
sys_anon_allocate(size_t size, void **pointer)
{
	return sys_vm_map(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1,
	    0, pointer);
}

int
sys_anon_free(void *pointer, size_t size)
{
	mlibc::infoLogger() << "mlibc: sys_anon_free is a stub" << frg::endlog;
	return ENOTSUP;
}

#ifndef MLIBC_BUILDING_RTDL
void
sys_exit(int status)
{
	mlibc::infoLogger() << "mlibc: sys_exit is a stub" << frg::endlog;
}
#endif

#ifndef MLIBC_BUILDING_RTDL
int
sys_clock_get(int clock, time_t *secs, long *nanos)
{
	mlibc::infoLogger() << "mlibc: sys_clock_get is a stub" << frg::endlog;
	return 0;
}
#endif

int
sys_open(const char *path, int flags, int *fd)
{
	uintptr_t ret, err;
	ret = syscall2(kPXSysOpen, (uintptr_t)path, (uintptr_t)flags, &err);
	if (ret != -1ul) {
		*fd = ret;
		return 0;
	} else
		return -err;
}

int
sys_close(int fd)
{
	mlibc::infoLogger() << "mlibc: sys_close is a stub" << frg::endlog;
	return ENOTSUP;
}

int
sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read)
{
	uintptr_t ret, err;
	ret = syscall3(kPXSysRead, fd, (uintptr_t)buf, (uintptr_t)count, &err);
	if (ret != -1ul) {
		*bytes_read = ret;
		return 0;
	} else
		return -err;
}

#ifndef MLIBC_BUILDING_RTDL
int
sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written)
{
	mlibc::infoLogger() << "mlibc: sys_write is a stub" << frg::endlog;
	return ENOTSUP;
}
#endif

int
sys_seek(int fd, off_t offset, int whence, off_t *new_offset)
{
	uintptr_t ret, err;
	ret = syscall3(kPXSysSeek, fd, offset, whence, &err);
	if (ret != -1ul) {
		*new_offset = ret;
		return 0;
	} else
		return -err;
}

int
sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset,
    void **window)
{
	void *addr = hint;
	uintptr_t err;
	addr = (void *)syscall6(kPXSysMmap, (uintptr_t)addr, size, prot, flags,
	    fd, offset, &err);
	if (err == 0)
		*window = addr;
	return err;
}

int
sys_vm_unmap(void *pointer, size_t size)
{
	mlibc::infoLogger() << "mlibc: sys_vm_unmap is a stub" << frg::endlog;
	return ENOTSUP;
}

int
sys_futex_wait(int *pointer, int expected, const struct timespec *time)
{
	mlibc::infoLogger() << "mlibc: sys_futex_wait is a stub" << frg::endlog;
	return ENOTSUP;
}

int
sys_futex_wake(int *pointer)
{
	mlibc::infoLogger() << "mlibc: sys_futex_wake is a stub" << frg::endlog;
	return ENOTSUP;
}

// All remaining functions are disabled in ldso.
#ifndef MLIBC_BUILDING_RTDL
int
sys_clone(void *entry, void *user_arg, void *tcb, pid_t *tid_out)
{
	mlibc::infoLogger() << "mlibc: sys_clone is a stub" << frg::endlog;
	return ENOTSUP;
}

void
sys_thread_exit()
{
	mlibc::infoLogger()
	    << "mlibc: sys_thread_exit is a stub" << frg::endlog;
	__builtin_trap();
}

int
sys_sleep(time_t *secs, long *nanos)
{
	long ms = (*nanos / 1000000) + (*secs * 1000);
	mlibc::infoLogger() << "mlibc: sys_sleep is a stub" << frg::endlog;
	return ENOTSUP;
}

int
sys_fork(pid_t *child)
{
	mlibc::infoLogger() << "mlibc: sys_fork is a stub" << frg::endlog;
	return ENOTSUP;
}

int
sys_execve(const char *path, char *const argv[], char *const envp[])
{
	mlibc::infoLogger() << "mlibc: sys_execve is a stub" << frg::endlog;
	return ENOTSUP;
}

pid_t
sys_getpid()
{
	pid_t pid = 1;
	mlibc::infoLogger() << "mlibc: sys_getpid is a stub" << frg::endlog;
	return pid;
}
pid_t
sys_getppid()
{
	pid_t ppid = 0;
	mlibc::infoLogger() << "mlibc: sys_getppid is a stub" << frg::endlog;
	return ppid;
}

#endif // MLIBC_BUILDING_RTDL

} // namespace mlibc
