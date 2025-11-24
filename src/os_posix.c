/*
 * Public domain
 *
 * BSD socket emulation code for Winsock2
 * File IO compatibility shims
 * Brent Cook <bcook@openbsd.org>
 * Kinichiro Inoguchi <inoguchi@openbsd.org>
 *
 * pipe2/pipe/socketpair emulation
 * Brent Cook <bcook@openbsd.org>
 *
 * pread and pwrite
 * Kinichiro Inoguchi <inoguchi@openbsd.org>
 */

#define NO_REDEF_POSIX_FUNCTIONS

#include "events_internal.h"

#define INIT_SZ	128

#ifndef va_copy
#  ifdef HAVE___VA_COPY
#   define va_copy(dest, src) __va_copy(dest, src)
#  else
#   define va_copy(dest, src) (dest) = (src)
#  endif
#endif

#undef accept
#undef listen
#undef read
#undef write
#undef close

void posix_perror(const char *s) {
	fprintf(stderr, "%s: %s\n", s, strerror(errno));
}

int posix_rename(const char *oldpath, const char *newpath) {
	return MoveFileEx(oldpath, newpath, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
}

static int wsa_errno(int err) {
	switch (err) {
		case WSAENOBUFS:
			errno = ENOMEM;
			break;
		case WSAEACCES:
			errno = EACCES;
			break;
		case WSANOTINITIALISED:
			errno = EPERM;
			break;
		case WSAEHOSTUNREACH:
		case WSAENETDOWN:
			errno = EIO;
			break;
		case WSAEFAULT:
			errno = EFAULT;
			break;
		case WSAEINTR:
			errno = EINTR;
			break;
		case WSAEINVAL:
			errno = EINVAL;
			break;
		case WSAEINPROGRESS:
			errno = EINPROGRESS;
			break;
		case WSAEWOULDBLOCK:
			errno = EAGAIN;
			break;
		case WSAEOPNOTSUPP:
			errno = ENOTSUP;
			break;
		case WSAEMSGSIZE:
			errno = EFBIG;
			break;
		case WSAENOTSOCK:
			errno = ENOTSOCK;
			break;
		case WSAENOPROTOOPT:
			errno = ENOPROTOOPT;
			break;
		case WSAECONNREFUSED:
			errno = ECONNREFUSED;
			break;
		case WSAEAFNOSUPPORT:
			errno = EAFNOSUPPORT;
			break;
		case WSAEBADF:
			errno = EBADF;
			break;
		case WSAENETRESET:
		case WSAENOTCONN:
		case WSAECONNABORTED:
		case WSAECONNRESET:
		case WSAESHUTDOWN:
		case WSAETIMEDOUT:
			errno = EPIPE;
			break;
	}
	return -1;
}

/*
 * Employ a similar trick to cpython (pycore_fileutils.h) where the CRT report
 * handler is disabled while checking if a descriptor is a socket or a file
 */
#if defined _MSC_VER && _MSC_VER >= 1900

#include <crtdbg.h>

static void noop_handler(const wchar_t *expression, const wchar_t *function,
	const wchar_t *file, unsigned int line, uintptr_t pReserved) {
	return;
}

#define BEGIN_SUPPRESS_IPH \
	int old_report_mode = _CrtSetReportMode(_CRT_ASSERT, 0); \
	_invalid_parameter_handler old_handler = _set_thread_local_invalid_parameter_handler(noop_handler)
#define END_SUPPRESS_IPH \
	_CrtSetReportMode(_CRT_ASSERT, old_report_mode); \
	_set_thread_local_invalid_parameter_handler(old_handler)

#else

#define BEGIN_SUPPRESS_IPH
#define END_SUPPRESS_IPH

#endif

int is_socket(int fd) {
	if (fd < 3)
		return 0;
	WSANETWORKEVENTS events;
	return (WSAEnumNetworkEvents((SOCKET)fd, NULL, &events) == 0);
}

 static int is_socket_ex(int fd) {
	intptr_t hd;

	BEGIN_SUPPRESS_IPH;
	hd = _get_osfhandle(fd);
	END_SUPPRESS_IPH;

	if (hd == (intptr_t)INVALID_HANDLE_VALUE) {
		return 1; /* fd is not file descriptor */
	}

	return 0;
}

int posix_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int rc = connect(sockfd, addr, addrlen);
	if (rc == SOCKET_ERROR)
		return wsa_errno(WSAGetLastError());
	return rc;
}

int posix_close(int fd) {
	int rc;

	if (is_socket(fd)) {
		if ((rc = closesocket(fd)) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			rc = wsa_errno(err);
		}
	} else {
		rc = _close(fd);
	}
	return rc;
}

ssize_t posix_read(int fd, void *buf, size_t count) {
	ssize_t rc;

	if (is_socket(fd)) {
		if ((rc = recv(fd, buf, count, 0)) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			rc = wsa_errno(err);
		}
	} else {
		rc = _read(fd, buf, count);
	}
	return rc;
}

ssize_t posix_write(int fd, const void *buf, size_t count) {
	ssize_t rc;
	if (is_socket(fd)) {
		if ((rc = send(fd, buf, count, 0)) == SOCKET_ERROR) {
			rc = wsa_errno(WSAGetLastError());
		}
	} else {
		rc = _write(fd, buf, count);
	}
	return rc;
}

int posix_getsockopt(int sockfd, int level, int optname,
	void *optval, socklen_t *optlen) {
	int rc;
	if (is_socket(sockfd)) {
		rc = getsockopt(sockfd, level, optname, (char *)optval, optlen);
		if (rc != 0) {
			rc = wsa_errno(WSAGetLastError());
		}
	} else {
		rc = -1;
	}
	return rc;
}

int posix_setsockopt(int sockfd, int level, int optname,
	const void *optval, socklen_t optlen) {
	int rc;
	if (is_socket(sockfd)) {
		rc = setsockopt(sockfd, level, optname, (char *)optval, optlen);
		if (rc != 0) {
			rc = wsa_errno(WSAGetLastError());
		}
	} else {
		rc = -1;
	}
	return rc;
}

ssize_t pwrite(int d, const void *buf, size_t nbytes, off_t offset) {
	off_t cpos, opos, rpos;
	ssize_t bytes;
	if ((cpos = lseek(d, 0, SEEK_CUR)) == -1)
		return -1;
	if ((opos = lseek(d, offset, SEEK_SET)) == -1)
		return -1;
	if ((bytes = _write(d, buf, nbytes)) == -1)
		return -1;
	if ((rpos = lseek(d, cpos, SEEK_SET)) == -1)
		return -1;
	return bytes;
}

ssize_t pread(int d, void *buf, size_t nbytes, off_t offset) {
	off_t cpos, opos, rpos;
	ssize_t bytes;
	if ((cpos = lseek(d, 0, SEEK_CUR)) == -1)
		return -1;
	if ((opos = lseek(d, offset, SEEK_SET)) == -1)
		return -1;
	if ((bytes = _read(d, buf, nbytes)) == -1)
		return -1;
	if ((rpos = lseek(d, cpos, SEEK_SET)) == -1)
		return -1;
	return bytes;
}

static int setfd(int fd, int flag) {
	int rc = -1;
	if (flag & FD_CLOEXEC) {
		HANDLE h = (HANDLE)_get_osfhandle(fd);
		if (h != NULL)
			rc = SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0) == 0 ? -1 : 0;
	}
	return rc;
}

static int setfl(int fd, int flag) {
	int rc = -1;
	if (flag & O_NONBLOCK) {
		long mode = 1;
		rc = ioctlsocket(fd, FIONBIO, &mode);
	}
	return rc;
}

int posix_pipe(int fildes[2]) {
	return socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, PF_UNSPEC, _2socket(fildes));
}

int pipe2(int fildes[2], int flags) {
	int rc = posix_pipe(fildes);
	if (rc == 0) {
		if (flags & O_NONBLOCK) {
			rc |= setfl(fildes[0], O_NONBLOCK);
			rc |= setfl(fildes[1], O_NONBLOCK);
		}
		if (flags & O_CLOEXEC) {
			rc |= setfd(fildes[0], FD_CLOEXEC);
			rc |= setfd(fildes[1], FD_CLOEXEC);
		}
		if (rc != 0) {
			int e = errno;
			posix_close(fildes[0]);
			posix_close(fildes[1]);
			errno = e;
		}
	}
	return rc;
}

int getcontext(ucontext_t *ucp) {
	int ret;

	/* Retrieve the full machine context */
	ucp->uc_mcontext.ContextFlags = CONTEXT_FULL;
	ret = GetThreadContext(GetCurrentThread(), &ucp->uc_mcontext);

	return (ret == 0) ? -1 : 0;
}

int setcontext(const ucontext_t *ucp) {
	int ret;

	/* Restore the full machine context (already set) */
	ret = SetThreadContext(GetCurrentThread(), &ucp->uc_mcontext);
	return (ret == 0) ? -1 : 0;
}

int makecontext(ucontext_t *ucp, void (*func)(), int argc, ...) {
	int i;
	va_list ap;
	char *sp;

	/* Stack grows down */
	sp = (char *)(size_t)ucp->uc_stack.ss_sp + ucp->uc_stack.ss_size;

	/* Reserve stack space for the arguments (maximum possible: argc*(8 bytes per argument)) */
	sp -= argc * 8;

	if (sp < (char *)ucp->uc_stack.ss_sp) {
		/* errno = ENOMEM;*/
		return -1;
	}

	/* Set the instruction and the stack pointer */
#if defined(_X86_)
	ucp->uc_mcontext.Eip = (unsigned long long)func;
	ucp->uc_mcontext.Esp = (unsigned long long)(sp - 4);
#else
	ucp->uc_mcontext.Rip = (unsigned long long)func;
	ucp->uc_mcontext.Rsp = (unsigned long long)(sp - 40);
#endif
	/* Save/Restore the full machine context */
	ucp->uc_mcontext.ContextFlags = CONTEXT_FULL;

	/* Copy the arguments */
	va_start(ap, argc);
	for (i = 0; i < argc; i++) {
		memcpy(sp, ap, 8);
		ap += 8;
		sp += 8;
	}
	va_end(ap);

	return 0;
}

int swapcontext(ucontext_t *oucp, const ucontext_t *ucp) {
	int ret;

	if (oucp == NULL || (void *)ucp == NULL) {
		/*errno = EINVAL;*/
		return -1;
	}

	ret = getcontext(oucp);
	if (ret == 0) {
		ret = setcontext(ucp);
	}
	return ret;
}
