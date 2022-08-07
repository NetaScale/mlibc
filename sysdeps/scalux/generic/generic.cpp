#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <asm/ioctls.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

namespace mlibc {

/*! debug/misc */

void sys_libc_log(const char *message) {
	(void)message;
	return;
}

void sys_libc_panic() {
    
}

/*! processes*/

void sys_exit(int status){
	__builtin_unreachable();
}

int sys_tcb_set(void *pointer) {
    return ENOSYS;
}

/*! vm */

int sys_anon_allocate(size_t size, void **pointer) {
	return ENOSYS;
}

int sys_anon_free(void *pointer, size_t size) {
    return ENOSYS;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	__ensure(!"sys_vm_map is a stub!");
}

int sys_vm_unmap(void* address, size_t size) {
	__ensure(!"sys_vm_unmap is a stub!");
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
	(void)pointer;
	(void)expected;
	(void)time;
	__ensure(!"sys_futex is a stub!");
	__builtin_unreachable();
}

int sys_futex_wake(int *pointer) {
	(void)pointer;
	__ensure(!"sys_futex is a stub!");
	__builtin_unreachable();
}

/*! file ops */

int sys_open(const char *path, int flags, mode_t mode, int *fd) {
	__ensure(!"sys_open is a stub!");
}

int sys_close(int) {
	__ensure(!"sys_close is a stub!");
}


int sys_read(int fd, void *buffer, size_t size, ssize_t *bytes_read) {
	return ENOSYS;
}

int sys_write(int fd, const void *buffer, size_t size, ssize_t *bytes_written) {
	return ENOSYS;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	return ENOSYS;
}

/*! timing */
int sys_clock_get(int clock, time_t *secs, long *nanos) {
	*secs = 0;
	*nanos = 0;
	return 0;
}

} // namespace mlibc
