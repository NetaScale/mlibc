
if disable_posix_option
	subdir_done()
endif
libc_sources += files(
	'generic/arpa-inet-stubs.cpp',
	'generic/dirent-stubs.cpp',
	'generic/dlfcn-stubs.cpp',
	'generic/fcntl-stubs.cpp',
	'generic/ftw-stubs.cpp',
	'generic/grp-stubs.cpp',
	'generic/langinfo-stubs.cpp',
	'generic/libgen-stubs.cpp',
	'generic/lookup.cpp',
	'generic/netdb-stubs.cpp',
	'generic/net-if-stubs.cpp',
	'generic/posix_ctype.cpp',
	'generic/posix-file-io.cpp',
	'generic/posix_locale.cpp',
	'generic/posix_signal.cpp',
	'generic/posix_stdio.cpp',
	'generic/posix_stdlib.cpp',
	'generic/posix_string.cpp',
	'generic/posix_time.cpp',
	'generic/pthread-stubs.cpp',
	'generic/pwd-stubs.cpp',
	'generic/resolv_conf.cpp',
	'generic/sched-stubs.cpp',
	'generic/spawn-stubs.cpp',
	'generic/strings-stubs.cpp',
	'generic/services.cpp',
	'generic/sys-file-stubs.cpp',
	'generic/syslog-stubs.cpp',
	'generic/sys-mman-stubs.cpp',
	'generic/sys-resource-stubs.cpp',
	'generic/sys-select-stubs.cpp',
	'generic/sys-shm.cpp',
	'generic/sys-socket-stubs.cpp',
	'generic/sys-statfs-stubs.cpp',
	'generic/sys-stat-stubs.cpp',
	'generic/sys-statvfs-stubs.cpp',
	'generic/sys-times.cpp',
	'generic/sys-time-stubs.cpp',
	'generic/sys-uio.cpp',
	'generic/sys-utsname.cpp',
	'generic/sys-wait-stubs.cpp',
	'generic/termios-stubs.cpp',
	'generic/unistd-stubs.cpp',
	'generic/utime-stubs.cpp',
	'generic/ucontext-stubs.cpp',
	'generic/semaphore-stubs.cpp',
	'generic/search.cpp',
	'generic/sys-msg.cpp',
	'generic/sys-sem.cpp',
	'generic/sys-ipc.cpp',
	'generic/time.cpp',
	'generic/wordexp-stubs.cpp'
)

if not headers_only
	libc_sublibs += static_library('musl-generic-regex',
		'musl-generic-regex/fnmatch.c',
		'musl-generic-regex/glob.c',
		'musl-generic-regex/regcomp.c',
		'musl-generic-regex/regerror.c',
		'musl-generic-regex/regexec.c',
		'musl-generic-regex/tre-mem.c',
		pic: true,
		include_directories: libc_include_dirs,
		c_args: ['-Wno-unused', '-Wno-implicit', '-Wno-parentheses', '-Wno-sign-compare', '-Wno-attributes', '-Wno-unknown-pragmas', '-Wno-implicit-fallthrough']
	)
endif

if not no_headers
	install_headers(
		'include/byteswap.h',
		'include/dirent.h',
		'include/dlfcn.h',
		'include/fcntl.h',
		'include/fnmatch.h',
		'include/ftw.h',
		'include/glob.h',
		'include/grp.h',
		'include/langinfo.h',
		'include/libgen.h',
		'include/netdb.h',
		'include/nl_types.h',
		'include/pthread.h',
		'include/pwd.h',
		'include/poll.h',
		'include/regex.h',
		'include/sched.h',
		'include/search.h',
		'include/spawn.h',
		'include/strings.h',
		'include/syslog.h',
		'include/termios.h',
		'include/unistd.h',
		'include/utime.h',
		'include/ucontext.h',
		'include/wordexp.h',
		'include/semaphore.h',
		'include/mqueue.h',
	)
	install_headers(
		'include/arpa/inet.h',
		subdir: 'arpa'
	)
	install_headers(
		'include/net/if.h',
		subdir: 'net'
	)
	install_headers(
		'include/netinet/in.h',
		'include/netinet/ip.h',
		'include/netinet/tcp.h',
		subdir: 'netinet'
	)
	install_headers(
		'include/sys/file.h',
		'include/sys/ipc.h',
		'include/sys/mman.h',
		'include/sys/msg.h',
		'include/sys/param.h',
		'include/sys/poll.h',
		'include/sys/resource.h',
		'include/sys/select.h',
		'include/sys/sem.h',
		'include/sys/shm.h',
		'include/sys/socket.h',
		'include/sys/statfs.h',
		'include/sys/stat.h',
		'include/sys/statvfs.h',
		'include/sys/termios.h',
		'include/sys/time.h',
		'include/sys/times.h',
		'include/sys/ttydefaults.h',
		'include/sys/types.h',
		'include/sys/uio.h',
		'include/sys/un.h',
		'include/sys/utsname.h',
		'include/sys/vfs.h',
		'include/sys/wait.h',
		'include/sys/syslog.h',
		subdir: 'sys'
	)
	install_headers(
		'include/bits/posix/id_t.h',
		'include/bits/posix/in_addr_t.h',
		'include/bits/posix/in_port_t.h',
		'include/bits/posix/iovec.h',
		'include/bits/posix/locale_t.h',
		'include/bits/posix/posix_ctype.h',
		'include/bits/posix/posix_locale.h',
		'include/bits/posix/posix_signal.h',
		'include/bits/posix/posix_stdio.h',
		'include/bits/posix/posix_stdlib.h',
		'include/bits/posix/posix_string.h',
		'include/bits/posix/posix_time.h',
		'include/bits/posix/posix_wctype.h',
		'include/bits/posix/stat.h',
		'include/bits/posix/timeval.h',
		'include/bits/posix/fd_set.h',
		'include/bits/posix/pthread_t.h',
		'include/bits/posix/timer_t.h',
		subdir: 'bits/posix'
	)
endif

