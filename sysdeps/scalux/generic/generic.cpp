#include <bits/ensure.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/thread-entry.hpp>

#include "../../Kernel/posix/sys.h"
#include "abi-bits/errno.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace mlibc {

void
sys_libc_log(const char *message)
{
	syscall1(kPXSysDebug, (uintptr_t)message, NULL);
}

void
sys_libc_panic()
{
	mlibc::infoLogger() << "\e[31mmlibc: panic!" << frg::endlog;
	asm volatile("syscall" : : "a"(12), "D"(1) : "rcx", "r11", "rdx");
	for (;;)
		;
}

int
sys_tcb_set(void *pointer)
{
	return syscall1(kPXSysSetFSBase, (uintptr_t)pointer, NULL);
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
	syscall1(kPXSysExit, status, NULL);
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
	uintptr_t err;
	syscall1(kPXSysClose, fd, &err);
	return err;
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
	uintptr_t ret, err;
	ret = syscall3(kPXSysWrite, fd, (uintptr_t)buf, (uintptr_t)count, &err);
	if (ret != -1ul) {
		*bytes_written = ret;
		return 0;
	} else
		return -err;
}

int
sys_ioctl(int fd, unsigned long request, void *arg, int *result)
{
	mlibc::infoLogger()
	    << "mlibc: " << __func__ << " is a stub! "
	    << "fd " << fd << "request " << request << frg::endlog;
	return ENOSYS;
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
		return err;
}

int
sys_isatty(int fd)
{
	uintptr_t ret, err;

	ret = syscall1(kPXSysIsATTY, fd, &err);

	if (ret == 1)
		return 0;
	else if (ret == -1ul)
		return err;

	__ensure(!"Not reached");
	return -1;
}

int
sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set,
    fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask,
    int *num_events)
{
	uintptr_t ret, err;

	ret = syscall6(kPXSysPSelect, num_fds, (uintptr_t)read_set,
	    (uintptr_t)write_set, (uintptr_t)except_set, (uintptr_t)timeout,
	    (uintptr_t)sigmask, &err);

	if (ret == -1ul)
		return err;

	*num_events = ret;
	return 0;
}

int
sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset,
    void **window)
{
	void     *addr = hint;
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
	// long ms = (*nanos / 1000000) + (*secs * 1000);
	mlibc::infoLogger() << "mlibc: sys_sleep is a stub" << frg::endlog;
	return ENOTSUP;
}

int
sys_fork(pid_t *child)
{
	uintptr_t err, pid;

	pid = syscall0(kPXSysFork, &err);
	if (err == 0)
		*child = pid;

	return err;
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

pid_t
sys_getpgid(pid_t pid, pid_t *pgid)
{
	mlibc::infoLogger() << "mlibc: sys_getpgid is a stub" << frg::endlog;
	*pgid = 0;
	return 0;
}

uid_t
sys_getuid()
{
	return 0;
}

gid_t
sys_getgid()
{
	return 0;
}

uid_t
sys_geteuid()
{
	return 0;
}

gid_t
sys_getegid()
{
	return 0;
}

/*
int
sys_sigprocmask(int how, const sigset_t *set, sigset_t *retrieve)
{
	return ENOTSUP;
}

int
sys_sigaction(int number, const struct sigaction *__restrict action,
    struct sigaction *__restrict saved_action)
{
	return ENOTSUP;
}
*/

int
sys_waitpid(pid_t pid, int *status, int flags, pid_t *ret_pid)
{
	uintptr_t ret, err;

	ret = syscall3(kPXSysWaitPID, pid, (uintptr_t)status, flags, &err);

	if (ret == -1ul)
		return err;

	*ret_pid = ret;
	return 0;
}

#endif // MLIBC_BUILDING_RTDL

} // namespace mlibc
