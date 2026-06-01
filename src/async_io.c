#include "events_internal.h"
#if defined(_MSC_VER) && !defined(ssize_t)
#	ifdef _WIN64
#		define ssize_t SSIZE_T
#	else
#		define ssize_t long
#	endif
#endif

fds_t async_socket(struct sockaddr *sa, char *address, int backlog, int protocol) {
	fds_t fd;
	int len, err, proto, off = 0, on = 1;
	char ipbuf[22] = {0};
	char *ip = ipbuf;
	u_saddr_t usa;
	struct sockaddr_un u_sa = {0};
	usa.sa = *sa;
	socklen_t sn = 0;
	uds_t uds = (protocol == -1) || sa->sa_family == AF_UNIX
		? (uds_t)events_calloc(1, sizeof(struct af_unix_s))
		: null;
	bool is_unix = !is_empty(uds);

	proto = protocol ? SOCK_STREAM : SOCK_DGRAM;
	if ((fd = socket(sa->sa_family, proto, (protocol ? IPPROTO_IP : IPPROTO_UDP))) < 0) {
		errno = os_geterror();
		if (is_unix)
			events_free(uds);
		return DATA_INVALID;
	}

	// set reuse flag for tcp
	if (!is_unix && protocol && getsockopt(fd, SOL_SOCKET, SO_TYPE, (void *)&on, &sn) >= 0) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) != 0) {
			/* Set reuse option, but don't abort on errors. */
			cerr("Cannot set socket option SO_REUSEADDR"CLR_LN);
		}
	}

	if (is_unix) {
		uds->addr = &events_get_sockaddr(fd)->sun;
		strncpy(uds->addr->sun_path, address, sizeof(uds->addr->sun_path) - 1);
		uds->addr->sun_family = AF_UNIX;
		uds->socket = fd;
		uds->type = DATA_UNIX;
		err = bind(fd, (struct sockaddr *)uds->addr, sizeof(uds->addr));
	} else {
		sn = sa->sa_family == AF_INET6 ? sizeof(usa.sin6) : sizeof(usa.sin);
		err = bind(fd, (struct sockaddr *)sa, sn);
		events_get_sockaddr(fd)->sa = *sa;
		if (!err && sa->sa_family == AF_INET6) {
			/* Could be 6 for IPv6 only or 10 (4+6) for IPv4+IPv6 */
			/* Set IPv6 only option, but don't abort on errors. */
			if (protocol > 6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&off, sizeof(off)) != 0) {
				cerr("cannot set socket option IPV6_V6ONLY=off"CLR_LN);
			} else if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on)) != 0) {
				cerr("cannot set socket option IPV6_V6ONLY=on"CLR_LN);
			}
		}
	}

	if (err < 0) {
		errno = os_geterror();
		close(fd);
		if (is_unix)
			events_free(uds);
		return -1;
	}

	if (proto == SOCK_STREAM) {
		if (listen(fd, backlog) != 0) {
			cerr("Cannot listen to %s: %d (%s)", address, os_geterror(), strerror(errno));
			close(fd);
			fd = INVALID_SOCKET;
			return fd;
		}
	}

	events_set_nonblocking(fd);
	events_target(socket2fd(fd))->uds = uds;
	return fd;
}

fds_t async_bind(char *address, int port, int backlog, int protocol) {
	fds_t fd;
	int err, proto, n = !protocol ? str_subcount(address, ".") : 0;
	char ipbuf[22] = {0};
	char *ip = ipbuf;
	struct sockaddr_in sa;
	socklen_t sn;
	struct hostent *he = {0};
	uds_t uds = (protocol == -1)
		? (uds_t)events_calloc(1, sizeof(struct af_unix_s))
		: null;
	bool is_unix = !is_empty(uds);

	if (!is_unix) {
		memset(&sa, 0, sizeof sa);
		sa.sin_family = AF_INET;
		if (!protocol || (address != OS_NULL && !str_is(address, events_hostname()))) {
			if (!protocol && (port || backlog) && n == 3) {
				ip = (char *)&backlog;
			} else {
				if ((he = async_gethostbyname(address)) == NULL) {
					errno = EDESTADDRREQ;
					return -1;
				}
				ip = (char *)he->h_addr;
			}

			n = 0;
			memmove(&sa.sin_addr, ip, 4);
		}

		sa.sin_port = htons(port);
	}

	proto = protocol ? SOCK_STREAM : SOCK_DGRAM;
	if ((fd = socket((is_unix ? AF_UNIX : AF_INET),
		proto, (protocol ? IPPROTO_IP : IPPROTO_UDP))) < 0) {
		errno = os_geterror();
		if (is_unix)
			events_free(uds);
		return -1;
	}

	// set reuse flag for tcp
	if (!is_unix && protocol && getsockopt(fd, SOL_SOCKET, SO_TYPE, (void *)&n, &sn) >= 0) {
		n = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof n);
	}

	if (is_unix) {
		uds->addr = &events_get_sockaddr(fd)->sun;
		strncpy(uds->addr->sun_path, address, sizeof(uds->addr->sun_path) - 1);
		uds->addr->sun_family = AF_UNIX;
		uds->socket = fd;
		uds->type = DATA_UNIX;
		err = bind(fd, (struct sockaddr *)uds->addr, sizeof(uds->addr));
	} else {
		err = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
		events_get_sockaddr(fd)->sin = sa;
	}

	if (err < 0) {
		errno = os_geterror();
		close(fd);
		if (is_unix)
			events_free(uds);
		return -1;
	}

	if (proto == SOCK_STREAM)
		listen(fd, backlog);

	events_set_nonblocking(fd);
	events_target(socket2fd(fd))->uds = uds;
	return fd;
}

fds_t async_accept(fds_t fd, char *server, int *port) {
	fds_t cfd;
	int one;
	u_saddr_t usa;
	struct sockaddr_in sa = {0};
	struct sockaddr_un u_sa = {0};
	uchar *ip;
	socklen_t len;
	bool is_unix = socket_is_uds(socket2fd(fd));

	async_wait(fd, 'r');
	len = is_unix ? sizeof(usa.sun) : sizeof(usa.sa);
	if ((cfd = accept(fd, (is_unix ? (struct sockaddr *)&usa.sun : (struct sockaddr *)&usa.sa), &len)) < 0) {
		errno = os_geterror();
		return -1;
	}

	events_get_sockaddr(cfd)->storage = usa.storage;
	if (!is_unix && server) {
		sa = usa.sin;
		ip = (uchar *)&sa.sin_addr;
		snprintf(server, 16, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	} else if (is_unix && server) {
		u_sa = usa.sun;
		snprintf(server, 108, "%s", u_sa.sun_path);
	}

	if (port)
		*port = ntohs(sa.sin_port);
	events_set_nonblocking(cfd);
	one = 1;
	if (is_unix)
		events_get_sockaddr(cfd)->sa.sa_family = AF_UNIX;
	else
		setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof one);

	return cfd;
}

fds_t async_connect(char *hostname, int port, int protocol) {
	fds_t fd;
	int err, ip_family = 0, proto, n = 0;
	u_saddr_t usa;
	u_saddr_t *sa;
	socklen_t sn;
	uds_t uds = (protocol == -1)
		? (uds_t)events_calloc(1, sizeof(struct af_unix_s))
		: null;
	bool is_unix = !is_empty(uds);

	if (!is_unix) {
		char host[ARRAY_SIZE] = {0};
		if (port)
			snprintf(host, sizeof(host) - 1, "%s:%d", hostname, port);
		else
			snprintf(host, sizeof(host) - 1, "%s", hostname);

		if (!async_parse_addr(host, &usa, &ip_family)) {
			errno = EDESTADDRREQ;
			return -1;
		}
	}

	proto = protocol ? SOCK_STREAM : SOCK_DGRAM;
	if ((fd = socket((is_unix ? AF_UNIX : usa.sa.sa_family),
		proto, (protocol ? IPPROTO_IP : IPPROTO_UDP))) < 0) {
		errno = os_geterror();
		if (is_unix)
			events_free(uds);
		return -1;
	}
	events_set_nonblocking(fd);

	// for udp
	if (!protocol) {
		n = 1;
		setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (const char *)&n, sizeof n);
	}

	// start connecting
	if (is_unix) {
		uds->addr = &events_get_sockaddr(fd)->sun;
		strncpy(uds->addr->sun_path, hostname, sizeof(uds->addr->sun_path) - 1);
		uds->addr->sun_family = AF_UNIX;
		uds->socket= fd;
		uds->type = DATA_UNIX;
		err = connect(fd, (struct sockaddr *)uds->addr, sizeof(uds->addr));
		sn = sizeof(sa->sun);
	} else {
		sa = events_get_sockaddr(fd);
		memset(sa, 0, sizeof *sa);
		memmove(&sa->storage, &usa.storage, sizeof(usa.storage));
		if (ip_family == 6) {
			err = connect(fd, &sa->sa, sizeof sa->sin6);
			sn = sizeof(sa->sin6);
		} else {
			err = connect(fd, &sa->sa, sizeof sa->sin);
			sn = sizeof(sa->sin);
		}
	}

	if (err < 0 && (os_geterror() != EINPROGRESS && os_geterror() != EAGAIN)) {
		close(fd);
		if (is_unix)
			events_free(uds);
		return -1;
	}

	// wait for finish
	async_wait(fd, 'w');
	if (getpeername(fd, (is_unix ? (struct sockaddr *)&sa->sun : &sa->sa), &sn) >= 0) {
		events_target(socket2fd(fd))->uds = uds;
		return fd;
	}

	// report error
	sn = sizeof n;
	getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&n, &sn);
	if (n == 0)
		errno = os_geterror();

	if (is_unix)
		events_free(uds);

	close(fd);
	return -1;
}

int async_read2(int fd, void *buf, int n) {
	int m;

	do
		async_wait(fd, 'r');
	while ((m = read(fd, buf, n)) < 0 && os_geterror() == EAGAIN);
	return m;
}

int async_read(int fd, void *buf, int n) {
	int m;

	while ((m = read(fd, buf, n)) < 0 && os_geterror() == EAGAIN)
		async_wait(fd, 'r');
	return m;
}

int async_write(int fd, void *buf, int n) {
	int m, tot;

	for (tot = 0; tot < n; tot += m) {
		while ((m = write(fd, (char *)buf + tot, n - tot)) < 0 && os_geterror() == EAGAIN)
			async_wait(fd, 'w');
		if (m < 0)
			return m;
		if (m == 0)
			break;
	}
	return tot;
}

static EVENTS_INLINE void *os_gethostbyname(param_t name) {
	struct hostent *he = {0};
	if ((he = gethostbyname(name->char_ptr)) != NULL)
		return (void *)he;

	return NULL;
}

int async_inet_pton(int af, const char *src, void *dst, size_t dstlen, int resolve_src) {
	struct addrinfo hints, *res, *ressave;
	int func_ret = 0;
	int gai_ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = af;
	if (!resolve_src) {
		hints.ai_flags = AI_NUMERICHOST;
	}

	gai_ret = events_is_active() && tasks_is_active()
		? async_getaddrinfo(src, NULL, &hints, &res)
		: getaddrinfo(src, NULL, &hints, &res);
	if (gai_ret != 0) {
		/* gai_strerror could be used to convert gai_ret to a string */
		/* POSIX return values: see
		 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/freeaddrinfo.html
		 */
		/* Windows return values: see
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520%28v=vs.85%29.aspx
		 */
		return 0;
	}

	ressave = res;

	while (res) {
		if ((dstlen >= (size_t)res->ai_addrlen)
			&& (res->ai_addr->sa_family == af)) {
			memcpy(dst, res->ai_addr, res->ai_addrlen);
			func_ret = 1;
		}
		res = res->ai_next;
	}

	freeaddrinfo(ressave);
	return func_ret;
}

int async_parse_addr(char *host, u_saddr_t *dst, int *ip_version) {
	unsigned int a, b, c, d;
	unsigned port;
	unsigned long portUL;
	int len;
	const char *cb;
	char *endptr;
	char buf[100] = {0};
	size_t ptrlen = strlen(host);

	memset(dst, 0, sizeof(u_saddr_t));
	dst->sin.sin_family = AF_INET;
	*ip_version = 0;

	/* Initialize len as invalid. */
	port = 0;
	len = 0;
	/* Test for different ways to format this string */
	if (sscanf(host,
		"%u.%u.%u.%u:%u%n",
		&a,
		&b,
		&c,
		&d,
		&port,
		&len) // NOLINT(cert-err34-c) 'sscanf' used to convert a string
			  // to an integer value, but function will not report
			  // conversion errors; consider using 'strtol' instead
		== 5) {
		/* Bind to a specific IPv4 address, e.g. 192.168.1.5:8080 */
		dst->sin.sin_addr.s_addr =
			htonl((a << 24) | (b << 16) | (c << 8) | d);
		dst->sin.sin_port = htons((uint16_t)port);
		*ip_version = 4;
		return 1;
	} else if (sscanf(host, "[%49[^]]]:%u%n", buf, &port, &len) == 2
		&& ((size_t)len <= ptrlen)
		&& async_inet_pton(AF_INET6, buf, &dst->sin6, sizeof(dst->sin6), 0)) {
		/* IPv6 address, examples: see above */
		/* dst->sin6.sin6_family = AF_INET6; already set by http_inet_pton */
		dst->sin6.sin6_port = htons((uint16_t)port);
		*ip_version = 6;
		return 1;
	} else if ((portUL = strtoul(host, &endptr, 0) && port <= 0xffff)
		&& (host != endptr)) {
		len = (int)(endptr - host);
		port = (uint16_t)portUL;
		/* If only port is specified, bind to IPv4, INADDR_ANY */
		dst->sin.sin_port = htons((uint16_t)port);
		*ip_version = 4;
		return 1;
	} else if ((cb = strchr(host, ':')) != NULL) {
		/* String could be a hostname. This check algorithm
		 * will only work for RFC 952 compliant hostnames,
		 * starting with a letter, containing only letters,
		 * digits and hyphen ('-'). Newer specs may allow
		 * more, but this is not guaranteed here, since it
		 * may interfere with rules for port option lists. */

		/* According to RFC 1035, hostnames are restricted to 255 characters
		 * in total (63 between two dots). */
		char hostname[ARRAY_SIZE];
		size_t hostnlen = (size_t)(cb - host);
		if ((hostnlen >= ptrlen) || (hostnlen >= sizeof(hostname))) {
			/* This would be invalid in any case */
			*ip_version = 0;
			return 0;
		}

		str_lcpy(hostname, host, hostnlen + 1);
		if (async_inet_pton(AF_INET, hostname, &dst->sin, sizeof(dst->sin), 1)) {
			if (sscanf(cb + 1, "%u%n", &port, &len)
				== 1) { // NOLINT(cert-err34-c) 'sscanf' used to convert a
						// string to an integer value, but function will not
						// report conversion errors; consider using 'strtol'
						// instead
				*ip_version = 4;
				dst->sin.sin_port = htons((uint16_t)port);
				len += (int)(hostnlen + 1);
				return 1;
			}
		} else if (async_inet_pton(AF_INET6, hostname, &dst->sin6, sizeof(dst->sin6), 1)) {
			if (sscanf(cb + 1, "%u%n", &port, &len) == 1) {
				*ip_version = 6;
				dst->sin6.sin6_port = htons((uint16_t)port);
				len += (int)(hostnlen + 1);
				return 1;
			}
		}
	} else if (host[0] == 'x') {
		/* unix (linux) domain socket */
		if (ptrlen < sizeof(dst->sun.sun_path)) {
			len = ptrlen;
			dst->sun.sun_family = AF_UNIX;
			memset(dst->sun.sun_path, 0, sizeof(dst->sun.sun_path));
			memcpy(dst->sun.sun_path, (char *)host + 1, ptrlen - 1);
			port = 0;
			*ip_version = 99;
			return 1;
		}
	}

	/* Reset ip_version to 0 if there is an error */
	*ip_version = 0;
	return 0;
}

EVENTS_INLINE char *gethostbyname_ip(struct hostent *host) {
	struct in_addr **p1 = (struct in_addr **)host->h_addr_list;
	return (char *)inet_ntop(AF_INET, p1[0], future_buffer(), INET_ADDRSTRLEN);
}

EVENTS_INLINE struct hostent *async_gethostbyname(char *hostname) {
	future *thrd = futures_pool();
	return (struct hostent *)queue_get(queue_work(thrd, os_gethostbyname, 2, hostname, thrd->buffer)).object;
}

static EVENTS_INLINE void *os_getnameinfo(param_t args) {
	return casting(getnameinfo((const struct sockaddr *)args[0].object, args[1].u_int,
		args[2].char_ptr, args[3].u_int, args[4].char_ptr, args[5].u_int, args[6].integer));
}

EVENTS_INLINE int async_getnameinfo(const struct sockaddr *sa, socklen_t salen,
	char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags) {
	return queue_get(queue_work(futures_pool(), os_getnameinfo, 7, sa, casting(salen), host,
		casting(hostlen), serv, casting(servlen), casting(flags))).integer;
}

static EVENTS_INLINE void *os_getaddrinfo(param_t args) {
	return casting(getaddrinfo(args[0].const_char_ptr, args[1].const_char_ptr,
		(const struct addrinfo *)args[2].object, (addrinfo_t)args[3].object));
}

EVENTS_INLINE int async_getaddrinfo(const char *name,
	const char *service, const struct addrinfo *hints, addrinfo_t result) {
	return queue_get(queue_work(futures_pool(), os_getaddrinfo, 4, name, service, hints, result)).integer;
}

static EVENTS_INLINE void *_os_open(param_t args) {
#ifdef _WIN32
	int r, flags = args[1].integer, mode = args[2].integer;
	flags |= O_BINARY;
	if (flags & O_CLOEXEC) {
		flags &= ~O_CLOEXEC;
		flags |= O_NOINHERIT;
	}

	flags &= ~O_NONBLOCK;
	r = _open(args[0].char_ptr, flags, mode);
#else
	int r = open(args[0].char_ptr, args[1].integer, args[2].integer);
#endif
	return casting(r);
}

static EVENTS_INLINE void *_os_read(param_t args) {
#ifdef _WIN32
	int r = _read(args[0].integer, args[1].object, args[2].u_int);
#else
	int r = read(args[0].integer, args[1].object, args[2].u_int);
#endif
	return casting(r);
}

static EVENTS_INLINE void *_os_write(param_t args) {
#ifdef _WIN32
	int r = _write(args[0].integer, args[1].const_char_ptr, args[2].u_int);
#else
	int r = write(args[0].integer, args[1].const_char_ptr, args[2].u_int);
#endif
	return casting(r);
}

static EVENTS_INLINE void *_os_sendfile(param_t args) {
#if defined(__APPLE__) || defined(__MACH__)
	return casting(sendfile(args[0].integer, args[1].integer, (off_t)args[2].long_long, (off_t *)args[3].long_long_ptr, NULL, 0));
#elif __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __DragonFly__
	return casting(sendfile(args[0].integer, args[1].integer, (off_t)args[2].long_long,
		(off_t *)args[3].long_long_ptr, NULL, 0, 0));
#else
	return casting(sendfile(args[0].integer, args[1].integer, (off_t *)args[2].long_long_ptr, args[3].max_size));
#endif
}

static EVENTS_INLINE void *_os_close(param_t args) {
#ifdef _WIN32
	int r = _close(args[0].integer);
#else
	int r = close(args[0].integer);
#endif
	return casting(r);
}

static EVENTS_INLINE void *_os_stat(param_t args) {
	return casting(stat(args[0].const_char_ptr, args[1].object));
}

static EVENTS_INLINE void *_os_fstat(param_t args) {
	return casting(fstat(args[0].integer, args[1].object));
}

static EVENTS_INLINE void *_os_access(param_t args) {
	return casting(access(args[0].const_char_ptr, args[1].integer));
}

static EVENTS_INLINE void *_os_unlink(param_t args) {
	return casting(unlink(args[0].const_char_ptr));
}

static EVENTS_INLINE void *_os_rmdir(param_t args) {
	return casting(rmdir(args[0].const_char_ptr));
}

static EVENTS_INLINE void *_os_mkdir(param_t args) {
	return casting(mkdir(args[0].const_char_ptr, args[1].u_short));
}

EVENTS_INLINE int fs_open(const char *path, int flag, int mode) {
	future *thrd = futures_pool();
	thrd->last_fd = TASK_DEAD;
	return queue_get(queue_work(thrd, _os_open, 3, path, casting(flag), casting(mode))).integer;
}

EVENTS_INLINE int fs_read(int fd, void *buf, uint32_t count) {
	return queue_get(queue_work(futures_pool(), _os_read, 3, casting(fd), buf, casting(count))).integer;
}

EVENTS_INLINE int fs_write(int fd, const void *buf, uint32_t count) {
	return queue_get(queue_work(futures_pool(), _os_write, 3, casting(fd), buf, casting(count))).integer;
}

EVENTS_INLINE ssize_t fs_sendfile(int fd_out, int fd_in, off_t *offset, size_t length) {
	return queue_get(queue_work(futures_pool(), _os_sendfile, 4,
		casting(fd_out), casting(fd_in), offset, casting(length))).long_long;
}

EVENTS_INLINE int fs_close(int fd) {
	future *thrd = futures_pool();
	if (thrd->last_fd == fd) {
		thrd->last_fd = TASK_ERRED;
		return TASK_ERRED;
	}

	int r = queue_get(queue_work(thrd, _os_close, 1, casting(fd))).integer;
	thrd->last_fd = fd;

	return r;
}

EVENTS_INLINE int fs_unlink(const char *path) {
	return queue_get(queue_work(futures_pool(), _os_unlink, 1, path)).integer;
}

EVENTS_INLINE int fs_rmdir(const char *path) {
	return queue_get(queue_work(futures_pool(), _os_rmdir, 1, path)).integer;
}

EVENTS_INLINE int fs_mkdir(const char *path, mode_t mode) {
	return queue_get(queue_work(futures_pool(), _os_mkdir, 2, path, casting(mode))).integer;
}

EVENTS_INLINE int fs_stat(const char *path, struct stat *st) {
	return queue_get(queue_work(futures_pool(), _os_stat, 2, path, st)).integer;
}

EVENTS_INLINE int fs_fstat(int fd, struct stat *st) {
	return queue_get(queue_work(futures_pool(), _os_fstat, 2, casting(fd), st)).integer;
}

EVENTS_INLINE int fs_access(const char *path, int mode) {
	return queue_get(queue_work(futures_pool(), _os_access, 2, path, casting(mode))).integer;
}

EVENTS_INLINE bool fs_exists(const char *path) {
	return fs_access(path, F_OK) == 0;
}

EVENTS_INLINE size_t fs_filesize(const char *path) {
	struct stat st;
	if (!fs_stat(path, &st))
		return (size_t)st.st_size;

	return 0;
}

EVENTS_INLINE bool fs_touch(const char *path) {
	return fs_writefile(path, "") == 0;
}

static EVENTS_INLINE void *_os_rename(param_t args) {
	return casting(rename((const void *)args[0].const_char_ptr, args[1].const_char_ptr));
}

EVENTS_INLINE int fs_rename(const char *oldfile, const char *newfile) {
	return queue_get(queue_work(futures_pool(), _os_rename, 2, oldfile, newfile)).integer;
}

static EVENTS_INLINE void *_os_copyfile(param_t args) {
	int err = copyfile((const void *)args[0].const_char_ptr, args[1].const_char_ptr);
#ifdef _WIN32
	return casting(err ? 0 : -1);
#else
	return casting(err);
#endif
}

EVENTS_INLINE int fs_copyfile(const char *oldfile, const char *newfile) {
	return queue_get(queue_work(futures_pool(), _os_copyfile, 2, oldfile, newfile)).integer;
}

int fs_writefile(const char *path, char *text) {
	int len, fd;
	if ((fd = fs_open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR)) > 0) {
		if ((len = (int)strlen(text)) > 0)
			len = fs_write(fd, text, len);

		if (!fs_close(fd))
			return len;
	}

	return task_code();
}

char *fs_readfile(const char *path) {
	char *buffer = null;
	int fd = 0;
	size_t len = fs_filesize(path);
	if (len > 0 && (fd = fs_open(path, O_RDONLY, 0)) > 0) {
		if (defer_free(buffer = events_calloc(1, len + 1))) {
			fs_read(fd, buffer, len);
			fs_close(fd);
		}
	}

	return buffer;
}

int fs_events(const char *path, watch_cb handler, void *filter) {
	int i, rid = TASK_ERRED;
	if (!is_data(sys_event.tasks_cpu_idx) || $size(sys_event.tasks_cpu_idx) == 0) {
		if (events_create_pool(events_create(60)) < 0) {
			perror("events_create_pool");
			return rid;
		}
	}

	if ((rid = fsevents_init(path, handler, filter)) > 0) {
		events_deque_t *q = sys_event.local[results_tid(rid)];
		atomic_flag_test_and_set(&q->started);
		yield();
	}

	return rid;
}

EVENTS_INLINE int fs_events_cancel(uint32_t rid) {
	return fsevents_stop(rid);
}

static void spawn_io(fds_t fd, int events, void *arg) {
	execinfo_t *info = (execinfo_t *)arg;
	spawn_cb func = info->io_func;
#ifndef _WIN32
	char data[Kb(32)] = {0};
	int count;
	if ((count = read((fds_t)info->read_output[0], data, sizeof(data))) > 0)
		func((fds_t)info->write_input[1], count, data);
#else
	func((fds_t)info->write_input[1], (size_t)events, info->buffer);
#endif
}

static void *spawning(param_t args) {
	process_t pid;
	execinfo_t *info = (execinfo_t *)args[2].object;
	tasks_t *t = active_task();
	char *command = args[0].char_ptr;
	int status = 0;
#ifdef _WIN32
	HANDLE ioThread = NULL;
#endif
	task_name("spawn #%d", task_id());
	pid = exec((const char *)command, args[1].const_char_ptr, info);
	if (info->io_func) {
#ifndef _WIN32
		status = events_add(futures_pool()->queue->loop, (fds_t)info->read_output[1], EVENTS_WRITE, 0, spawn_io, info);
#else
		status = -1;
		if (events_assign_fd(info->read_output[0], (intptr_t)pid)) {
			status = events_add(futures_pool()->queue->loop, (fds_t)pid, EVENTS_READ, 0, spawn_io, info);
			ioThread = CreateThread(0, Kb(16), spawn_io_thread, info, 0, NULL);
		}
#endif
	}

	if (!status && pid > 0) {
		info->context = t;
		yield();
		while (exec_wait(pid, 0, &status) && os_geterror() == ETIMEDOUT) {
			tasks_info(t, 1);
			yield();
		}

		info->context = NULL;
		if (info->io_func) {
#ifndef _WIN32
			events_del((fds_t)info->read_output[1]);
			close((uintptr_t)info->read_output[0]);
			close((uintptr_t)info->read_output[1]);
			close((uintptr_t)info->write_input[0]);
			close((uintptr_t)info->write_input[1]);
#else
			CloseHandle(ioThread);
			CloseHandle(info->write_input[1]);
			events_del((fds_t)pid);
			close((intptr_t)pid);
#endif
		}

		if (info->exit_func)
			info->exit_func(status, status);
	} else {
		fprintf(stderr, "Process launch failed with: %s"CLR_LN, strerror(os_geterror()));
	}

	return 0;
}

execinfo_t *spawn(const char *command, const char *args, spawn_cb io_func, exit_cb exit_func) {
	execinfo_t *info = exec_info(NULL, false, inherit, inherit, inherit);
	if (io_func) {
#ifdef _WIN32
		if (os_create_pipe("spawn_in", &info->write_input[0], &info->write_input[1])
			|| os_create_pipe("spawn_out", &info->read_output[0], &info->read_output[1])) {
			perror("os_create_pipe");
			return NULL;
		}
#elif defined(__APPLE__) || defined(__MACH__)
		if (pipe(_2fd(info->write_input))
			|| pipe(_2fd(info->read_output))) {
			perror("pipe");
			return NULL;
		}
		events_set_nonblocking(info->write_input[0]);
		events_set_nonblocking(info->write_input[1]);
		events_set_nonblocking(info->read_output[0]);
		events_set_nonblocking(info->read_output[1]);
#else
		if (pipe2(_2fd(info->write_input), O_NONBLOCK)
			|| pipe2(_2fd(info->read_output), O_NONBLOCK)) {
			perror("pipe2");
			return NULL;
		}
#endif
	}

	info->io_func = io_func;
	info->exit_func = exit_func;
	info->is_spawn = true;
	info->rid = task_push(create_task(Kb(64),
		(data_func_t)spawning, arrays(3, command, args, info), false, true), true);
	yield();
	return info->context == NULL ? NULL : info;
}

EVENTS_INLINE uintptr_t spawn_pid(execinfo_t *child) {
#ifdef _WIN32
	return (uintptr_t)GetProcessId(child->ps);
#else
	return (uintptr_t)child->ps;
#endif
}

EVENTS_INLINE bool spawn_is_finish(execinfo_t *child) {
	return !is_ptr_usable(child) || !is_ptr_usable(child->context) || task_is_terminated(child->context);
}

static EVENTS_INLINE void *_getentropy(param_t args) {
	return casting(getentropy(args[0].object, args[1].max_size));
}

EVENTS_INLINE int async_getentropy(void *buf, size_t buflen) {
	return queue_get(queue_work(futures_pool(), _getentropy, 2, buf, casting(buflen))).integer;
}

static EVENTS_INLINE void *_os__fprintf(param_t args) {
	return casting(fprintf(args[0].object, "%s", args[1].const_char_ptr));
}

static EVENTS_INLINE void *_os_fprintf(param_t args) {
	if (str_is_empty(args[0].const_char_ptr))
		return null;

	FILE *fi;
	if ((fi = fopen(args[0].const_char_ptr, args[1].const_char_ptr)) != NULL) {
		flockfile(fi);
		int count = fprintf(fi, "%s", args[2].const_char_ptr);
		if (count > 0)
			fflush(fi);

		funlockfile(fi);
		fclose(fi);
		if (count > 0)
			return casting(count);
	}

	return 0;
}

EVENTS_INLINE int async_fprintf(const char *path, const char *mode, const char *buf) {
	return queue_get(queue_work(futures_pool(), _os_fprintf, 3, path, mode, buf)).integer;
}

static EVENTS_INLINE void *_os_fwriter(param_t args) {
	if (str_is_empty(args[0].const_char_ptr))
		return null;

	FILE *fi;
	if ((fi = fopen(args[0].const_char_ptr, args[1].const_char_ptr)) != NULL) {
		flockfile(fi);
		int count = fwrite((const void *)args[2].object, args[3].max_size, args[4].max_size, fi);
		if (count > 0)
			fflush(fi);

		funlockfile(fi);
		fclose(fi);
		if (count > 0)
			return casting(count);
	}

	return 0;
}

EVENTS_INLINE int async_fwrite(const char *path, const char *mode,
	void *buf, size_t size, size_t count) {
	return queue_get(queue_work(futures_pool(), _os_fwriter, 5,
		path, mode, buf, casting(size), casting(count))).max_size;
}

static EVENTS_INLINE void *_os_fwrite(param_t args) {
	FILE *fi = (FILE *)args[3].object;
	int count = fwrite((const void *)args[0].object, args[1].max_size, args[2].max_size, fi);
	if (count > 0)
		fflush(fi);

	return casting(count);

}

EVENTS_INLINE size_t fs_fwrite(void *buf, size_t items_size, size_t items_count, FILE *stream) {
	return queue_get(queue_work(futures_pool(), _os_fwrite, 4, buf, casting(items_size), casting(items_count), stream)).max_size;
}

static EVENTS_INLINE void *_os_fopen(param_t args) {
	if (str_is_empty(args[0].const_char_ptr) || str_is_empty(args[1].const_char_ptr))
		return null;

	return fopen(args[0].const_char_ptr, args[1].const_char_ptr);
}

EVENTS_INLINE FILE *fs_fopen(const char *path, const char *mode) {
	return (FILE *)queue_get(promise_fopen(path, mode)).object;
}

static EVENTS_INLINE void *_os_fread(param_t args) {
	return casting(fread(args[0].object, args[1].max_size, args[2].max_size, (FILE *)args[3].object));
}

EVENTS_INLINE size_t fs_fread(void *buf, size_t items_size, size_t items_count, FILE *stream) {
	return queue_get(queue_work(futures_pool(), _os_fread, 4,
		buf, casting(items_size), casting(items_count), stream)).max_size;
}

static EVENTS_INLINE void *_os_fclose(param_t args) {
	return casting(fclose((FILE *)args[0].object));
}

EVENTS_INLINE int fs_fclose(FILE *stream) {
	return queue_get(queue_work(futures_pool(), _os_fclose, 1, stream)).integer;
}

#ifndef _WIN32
static EVENTS_INLINE void *_os_chmod(param_t args) {
	return casting(chmod(args[0].const_char_ptr, args[1].u_int));
}

EVENTS_INLINE int fs_chmod(const char *file, mode_t mode) {
	return queue_get(queue_work(futures_pool(), _os_chmod, 2, file, casting(mode))).integer;
}
#endif

static EVENTS_INLINE void *_os_fgetc(param_t args) {
	return casting(fgetc((FILE *)args[0].object));
}

EVENTS_INLINE int fs_fgetc(FILE *stream) {
	return queue_get(queue_work(futures_pool(), _os_fgetc, 1, stream)).integer;
}

static EVENTS_INLINE void *_os_fgets(param_t args) {
	return fgets(args[0].char_ptr, args[1].integer, (FILE *)args[2].object);
}

EVENTS_INLINE char *fs_fgets(char *buf, int count, FILE *stream) {
	return queue_get(queue_work(futures_pool(), _os_fgets, 3, buf, casting(count), stream)).char_ptr;
}

EVENTS_INLINE int promise_read(promise *p, int fd, void *buf, uint32_t count) {
	return promise_wait(promise_work(p, _os_read, 3, casting(fd), buf, casting(count))).integer;
}

EVENTS_INLINE char *promise_fgets(promise *p, char *buf, int count, FILE *stream) {
	return promise_wait(promise_work(p, _os_fgets, 3, buf, casting(count), stream)).char_ptr;
}

EVENTS_INLINE int promise_fgetc(promise *p, FILE *stream) {
	return promise_wait(promise_work(p, _os_fgetc, 1, stream)).integer;
}

EVENTS_INLINE int promise_fclose(promise *p, FILE *stream) {
	int r = DATA_INVALID;
	if (!is_empty(stream))
		r = promise_wait(promise_work(p, _os_fclose, 1, stream)).integer;

	promise_clean(p);
	return r;
}

EVENTS_INLINE promise *promise_fopen(const char *path, const char *mode) {
	return queue_work(futures_pool(), _os_fopen, 2, path, mode);
}

static EVENTS_INLINE void *_os_popen(param_t args) {
	if (str_is_empty(args[0].const_char_ptr) || str_is_empty(args[1].const_char_ptr))
		return null;

	return popen(args[0].const_char_ptr, args[1].const_char_ptr);
}

EVENTS_INLINE promise *promise_popen(const char *path, const char *mode) {
	return queue_work(futures_pool(), _os_popen, 2, path, mode);
}

static EVENTS_INLINE void *_os_pclose(param_t args) {
	return casting(pclose((FILE *)args[0].object));
}

EVENTS_INLINE int promise_pclose(promise *p, FILE *stream) {
	int r = DATA_INVALID;
	if (!is_empty(stream))
		r = promise_wait(promise_work(p, _os_pclose, 1, stream)).integer;

	promise_clean(p);
	return r;
}

EVENTS_INLINE size_t promise_fwrite(promise *p, void *buf, size_t items_size, size_t items_count, FILE *stream) {
	return promise_wait(promise_work(p, _os_fwrite, 4, buf,
		casting(items_size), casting(items_count), stream)).integer;
}

EVENTS_INLINE int promise_fprintf(promise *p, FILE *stream, const char *fmt) {
	return promise_wait(promise_work(p, _os__fprintf, 2, stream, fmt)).integer;
}
