/*
 * Copyright (c) 2009, Cybozu Labs, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * * Neither the name of the <ORGANIZATION> nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "events_internal.h"

#if defined __linux__ || defined _WIN32

#ifndef EVENTS_EPOLL_DEFER_DELETES
# define EVENTS_EPOLL_DEFER_DELETES 1
#endif

typedef struct events_epoll_s {
	events_t loop;
#ifdef _WIN32
	HANDLE epfd;
#else
	int epfd;
#endif
	struct epoll_event events[1024];
} events_epoll;

events_t *events_create(int max_timeout) {
	events_epoll *loop;

	/* init parent */
	assert(EVENTS_IS_INITD);
	if ((loop = (events_epoll *)events_malloc(sizeof(events_epoll))) == NULL) {
		return NULL;
	}
	if (events_init_loop_internal(&loop->loop, max_timeout) != 0) {
		events_free(loop);
		return NULL;
	}

	/* init myself */
#ifndef _WIN32
	if ((loop->epfd = epoll_create(sys_event.max_fd)) == -1)
#else
	if ((loop->epfd = epoll_create(sys_event.max_fd)) == NULL)
#endif
	{
		events_deinit_loop_internal(&loop->loop);
		events_free(loop);
		return NULL;
	}

	loop->loop.now = time(NULL);
	return &loop->loop;
}

int events_destroy(events_t *_loop) {
	events_epoll *loop = (events_epoll *)_loop;

	events_set_destroy();
	if (loop == NULL || epoll_close(loop->epfd) != 0) {
		return -1;
	}

	events_deinit_loop_internal(&loop->loop);
	events_free(loop);
	return 0;
}

int events_update_internal(events_t *_loop, int fd, int event) {
	events_epoll *loop = (events_epoll *)_loop;
	events_fd_t *target = events_target(fd);
	struct epoll_event ev;
	int epoll_ret;

	memset(&ev, 0, sizeof(ev));
	assert(EVENTS_FD_BELONGS_TO_LOOP(&loop->loop, fd));

	if ((event & EVENTS_READWRITE) == target->events) {
		return 0;
	}

	ev.events = ((event & EVENTS_READ || event == EVENTS_PATHWATCH) != 0 ? EPOLLIN : 0)
		| ((event & EVENTS_WRITE) != 0 ? EPOLLOUT : 0);
	ev.data.fd = fd;

#define SET(op, check_error) do {		    \
    epoll_ret = epoll_ctl(loop->epfd, op, fd2socket(fd), &ev); \
    assert(! check_error || epoll_ret == 0);	    \
  } while (0)

#if EVENTS_EPOLL_DEFER_DELETES

	if ((event & EVENTS_DEL) != 0) {
	  /* nothing to do */
	} else if ((event & EVENTS_READWRITE) == 0) {
		SET(EPOLL_CTL_DEL, 1);
	} else {
		SET(EPOLL_CTL_MOD, 0);
		if (epoll_ret != 0) {
			assert(errno == ENOENT);
			SET(EPOLL_CTL_ADD, 1);
		}
	}

#else

	if ((events & EVENTS_READWRITE) == 0) {
		SET(EPOLL_CTL_DEL, 1);
	} else {
		SET(target->events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, 1);
	}

#endif

#undef SET

	target->events = event;
	return 0;
}

intptr_t events_backend_fd(events_t *_loop) {
	return (intptr_t)((events_epoll *)_loop)->epfd;
}

int events_poll_once_internal(events_t *_loop, int max_wait) {
	events_epoll *loop = (events_epoll *)_loop;
	int i, nevents, ffd = 0;

	nevents = epoll_wait(loop->epfd, loop->events, sizeof(loop->events) / sizeof(loop->events[0]),
		(ffd > 0 ? 0 : max_wait * 1000));
	if (nevents == -1) {
		return -1;
	}
	for (i = 0; i < nevents; ++i) {
		struct epoll_event *event = loop->events + i;
		events_fd_t *target = events_target(event->data.fd);
		if (loop->loop.loop_id == target->loop_id
			&& (target->events & EVENTS_READWRITE) != 0) {
			int revents = ((event->events & EPOLLIN) != 0 ? EVENTS_READ : 0)
				| ((event->events & EPOLLOUT) != 0 ? EVENTS_WRITE : 0)
				| ((event->events & EPOLLHUP) != 0 ? EVENTS_CLOSED : 0);
			if (target->is_pathwatcher) {
				inotify_handler(event->data.fd, (inotify_t *)null, (watch_cb)target->callback);
			} else if (revents != 0) {
				(*target->callback)(event->data.fd, revents, target->cb_arg);
			}
		} else {
#if EVENTS_EPOLL_DEFER_DELETES
			event->events = 0;
			epoll_ctl(loop->epfd, EPOLL_CTL_DEL, event->data.fd, event);
#endif
		}
	}
	return 0;
}

#endif