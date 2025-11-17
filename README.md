# events

A *tiny*, *lightning fast* event loop.

This project takes up where [picoev](https://github.com/kazuho/picoev) left off, it forks and remake, bringing in aspects from [FastCGI_A_High-Performance_Web_Server_Interface_FastCGI.html](https://fastcgi-archives.github.io/FastCGI_A_High-Performance_Web_Server_Interface_FastCGI.html) source [fcgi2](https://github.com/FastCGI-Archives/fcgi2), specificity, how to make **Windows** `file descriptors` aka *fake* behave like on **Linux**. As such, this **events** library handles general non-blocking file I/O.

This system supports interfacing [epoll](https://en.wikipedia.org/wiki/Epoll), [kqueue](https://en.wikipedia.org/wiki/Kqueue), and [iocp](https://en.wikipedia.org/wiki/Input/output_completion_port) *thru* [wepoll](https://github.com/piscisaureus/wepoll). In reading [Practical difference between epoll and Windows IO Completion Ports (IOCP)](https://www.ulduzsoft.com/2014/01/practical-difference-between-epoll-and-windows-io-completion-ports-iocp/) discuss things where **wepoll** seem to fill.

**c-events** provides function wrappers to some **Linux** like *functionality*, exp. `mkfifo` for **Windows**. However, this project is base around *adding/registering* an `event` for an `file descriptor`, and you reacting using general platform/OS calls.
It differs from [libev](https://software.schmorp.de/pkg/libev.html), [libeio](https://software.schmorp.de/pkg/libeio.html), [libevent](https://libevent.org/), and [libuv](http://libuv.org/). It *does not* provide complete handling using special functions. It's more geared towards a supplement to **libuv**, for more finer grain control.

Some **Libevent** [examples](https://github.com/libevent/libevent/tree/master/sample) and [tests](https://github.com/libevent/libevent/tree/master/test) have been brought in and modified for *basic* testing this library.

## features

**events** provides a mechanism to execute a callback function when a specific event occurs on a file descriptor or after a timeout has been reached. Every event represents a set of conditions, including:

* A file descriptor being ready to read from or write to,
 `events_add(loop, listen_sock, EVENTS_READ | EVENTS_WRITE, 0, accept_callback, NULL)`.
* A file descriptor has close,
 `events_add(loop, listen_sock, EVENTS_READ | EVENTS_CLOSE, 0, accept_callback, NULL)`.
* A timeout expiring on file descriptor in **5** secods,
 `events_add(loop, listen_sock, EVENTS_READ | EVENTS_TIMEOUT, 5, accept_callback, NULL)`.
* A signal occurring,
 `events_add(loop, SIGINT, EVENTS_SIGNAL, 0, signal_cb, NULL)`.
* A user-triggered event, execute in **500** milliseconds,
 `actor_t *actor = events_actor(loop, 500, actor_cb, NULL)`, `events_repeat_actor(actor, seconds(2))`, `events_clear_actor(actor)`.

Once you call `events_init(1024)` and `events_t *loop = events_create(60)` functions to set up an events and associate it with an *event* **loop**, it becomes initialized. At this point, you can add ~file descriptors~, which makes it *active* in the *loop*.

When the conditions that would trigger an event occur (e.g., its file descriptor changes state or its timeout expires), the event becomes *ready*, and its (user-provided) callback function is run. All events are *persistent*, until `events_del(listen_sock)` is called, only user-triggered are one off, if not set to repeat. MUST call `events_once(loop, 5)` to monitor for changes, add a wait time in *seconds*, SHOULD be combined with `events_is_running(loop)` to ensure all events are captured.

## usage

```c
#include <events.h>

static void fifo_read(sockfd_t fd, int event, void *arg) {
 char buf[255];
 int len;

 fprintf(stderr, "fifo_read called with fd: %d, event: %d, arg: %p\n", socket2fd(fd), event, arg);
 len = read(fd, buf, sizeof(buf) - 1);
 if (len <= 0) {
  if (len == -1)
   perror("read");
  else if (len == 0)
   fprintf(stderr, "Connection closed\n");
  events_del(fd);
  return;
 }

 buf[len] = '\0';
 fprintf(stdout, "Read: %s\n", buf);
}

static void signal_cb(sockfd_t sig, int event, void *arg) {
 events_t *loop = events_loop(sig);
 unlink(mkfifo_name());
 events_destroy(loop);
}

int main(int argc, char **argv) {
 events_t *base;
 struct stat st;
 const char *fifo = "event.fifo";
 int socket;

 if (lstat(fifo, &st) == 0) {
  if ((st.st_mode & S_IFMT) == S_IFREG) {
   errno = EEXIST;
   perror("lstat");
   exit(1);
  }
 }

 unlink(fifo);
 if (mkfifo(fifo, 0600) == -1) {
  perror("mkfifo");
  exit(1);
 }

 /* Initialize the event library */
 base = events_create(6);

 socket = open(fifo, O_RDWR | O_NONBLOCK, 0);
 if (socket == -1) {
  perror("open");
  unlink(mkfifo_name());
  events_destroy(base);
  exit(1);
 }

 fprintf(stderr, "Write data to %s\n", mkfifo_name());

 /* catch SIGINT so that event.fifo can be cleaned up*/
 events_add(base, SIGINT, EVENTS_SIGNAL, 0, signal_cb, NULL);

 /* Initialize one event */
 events_add(base, socket, EVENTS_READ, 0, fifo_read, NULL);

 while (events_is_running(base)) {
  events_once(base, 1);
 }

 close(socket);
 unlink(fifo);
 events_destroy(base);

 return (0);
}
```
