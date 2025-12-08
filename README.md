# events

A *tiny*, *lightning fast* event loop.

This project takes up where [picoev](https://github.com/kazuho/picoev) left off, it forks and remake, bringing in aspects from [FastCGI_A_High-Performance_Web_Server_Interface_FastCGI.html](https://fastcgi-archives.github.io/FastCGI_A_High-Performance_Web_Server_Interface_FastCGI.html) source [fcgi2](https://github.com/FastCGI-Archives/fcgi2), specificity, how to make **Windows** `file descriptors` aka *fake* behave like on **Linux**. As such, this **events** library handles general non-blocking file I/O.

This system supports interfacing [epoll](https://en.wikipedia.org/wiki/Epoll), [kqueue](https://en.wikipedia.org/wiki/Kqueue), and [iocp](https://en.wikipedia.org/wiki/Input/output_completion_port) *thru* [wepoll](https://github.com/piscisaureus/wepoll). In reading [Practical difference between epoll and Windows IO Completion Ports (IOCP)](https://www.ulduzsoft.com/2014/01/practical-difference-between-epoll-and-windows-io-completion-ports-iocp/) discuss things where **wepoll** seem to fill.

**c-events** provides function wrappers to some **Linux** like *functionality*, exp. `mkfifo` for **Windows**. However, this project is base around *adding/registering* an `event` for an `file descriptor`, and you reacting using general platform/OS calls.
It differs from [libev](https://software.schmorp.de/pkg/libev.html), [libeio](https://software.schmorp.de/pkg/libeio.html), [libevent](https://libevent.org/), and [libuv](http://libuv.org/). It *does not* provide complete handling using special functions. It's more geared towards a supplement to **libuv**, for more finer grain control.

Some **Libevent** [examples](https://github.com/libevent/libevent/tree/master/sample) and [tests](https://github.com/libevent/libevent/tree/master/test) have been brought in and modified for *basic* testing this library.

## Table of Contents

* [Features](#features)
* [Design](#design)
  * [API layout](#api)
* [Synopsis](#synopsis)
* [Usage](#usage)
* [Installation](#installation)
* [Contributing](#contributing)
* [License](#license)

## Features

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

## Design

### API

## Synopsis

## Usage

```c

```

## Installation

Any **commit** with an **tag** is considered *stable* for **release** at that *version* point.

If there are no *binary* available for your platform under **Releases** then build using **cmake**,
which produces **static** libraries by default.

### Linux

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug/Release -D BUILD_TESTS=OFF -D BUILD_EXAMPLES=OFF # use to not build tests and examples
cmake --build .
```

### Windows

```shell
mkdir build
cd build
cmake .. -D BUILD_TESTS=OFF -D BUILD_EXAMPLES=OFF # use to not build tests and examples
cmake --build . --config Debug/Release
```

### As cmake project dependency

> For **CMake** versions earlier than `3.14`, see <https://cmake.org/cmake/help/v3.14/module/FetchContent.html>

Add to **CMakeLists.txt**

```c
find_package(events QUIET)
if(NOT events_FOUND)
    FetchContent_Declare(events
        URL https://github.com/zelang-dev/c-events/archive/refs/tags/0.1.0.zip
        URL_MD5 0256bd86ca474383070bb1000d3f77c5
    )
    FetchContent_MakeAvailable(events)
endif()

target_include_directories(your_project PUBLIC $<BUILD_INTERFACE:${EVENTS_INCLUDE_DIR} $<INSTALL_INTERFACE:${EVENTS_INCLUDE_DIR})
target_link_libraries(your_project PUBLIC events)
```

## Contributing

Contributions are encouraged and welcome; I am always happy to get feedback or pull requests on Github :) Create [Github Issues](https://github.com/zelang-dev/c-events/issues) for bugs and new features and comment on the ones you are interested in.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
