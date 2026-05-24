# Httpi - a dual Web client/server and JavaScript processor

This *subproject* is a **WIP** implementation that follows up on [LibHTTP](https://github.com/lammertb/libhttp), and [CivetWeb](https://github.com/civetweb/civetweb), forks of [Mongoose](https://github.com/cesanta/mongoose). With ideas from [quickwebserver](https://github.com/QuickJS-Web-project/quickwebserver).

- Where as, all *parsing* and *actual communcations* replaced with **Events API**,
and other routines that's already implemented.
- Each incoming request *accepted* handled in *independent coroutines* aka **green threads**,
the `Events API` spread across a *thread pool* determented by number of core available.
- All *file system calls* handled by a different thread pool designed just for that purpose.
-
- Replace [Duktape](https://github.com/svaarala/duktape) with [QuickJS-NG](https://github.com/quickjs-ng/quickjs) for Direct JavaScript support. This came about after getting a better understanding of the layout from [QuickJS: An Overview and Guide to Adding a New Feature](https://blogs.igalia.com/compilers/2023/06/12/quickjs-an-overview-and-guide-to-adding-a-new-feature/) and [Building a Runtime with QuickJS](https://healeycodes.com/building-a-runtime-with-quickjs). It's really possible to build *Yet Another JavaScript* runtime *aka* Node.js, Bun, *etc...* replacement. For better **QuickJS-NG** documention on `API` see <https://www.mintlify.com/quickjs-ng/quickjs/introduction>.
- Remove direct CGI handling.
