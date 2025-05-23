# Dual-stack HTTPS server 

> [!IMPORTANT ]
> I'm currently moving to Go for such a project as it makes a lot more sense for what I want out of it. It can be looked at [here](https://github.com/DMGDy/go-https)

An HTTP server. I will see how far I can go with its use case. 
Potentially can replace [apache](https://httpd.apache.org/) on my personal website.
Would need to do many things for that to work.

## Building
This project uses [tsodings](https://github.com/tsoding) 
[nob.h](https://github.com/tsoding/nob.h/) for building.


Simply run `cc -o nob nob.c` and the binary will build as
`bin/server`

## Dependency
This project uses [openssl](https://www.openssl.org/)(3.5 release) and the build program `nob.c` is default set
the static library path `libssl.a` and `libcrypto.a` to be in the working
directory of this project. You may modify it to point to its actual location
on your machine or build it locally for this program like I did.

## TO-DO
I hopefully can get through most of these. Ordered in what I think in the moment
is the primary features I need working first. Will update as I find out more specifics.

1. [X] Parse HTTP Request and deliver HTML
    1. [X] Send files beyond index.html
2. [X] Add SSL/TLS encryption with openssl
3. [ ] Log accesses and responses
4. [ ] Handle `?fbclid=` from accessing from instagram.
5. [ ] Add concurrency
    1. [ ] ~~Multi-thread for multiple connections (maybe thread pool or semaphore approach)~~
    2. [ ] ~~Potentially move to C [coroutines](https://github.com/tsoding/coroutines).~~
    Written by [tsoding](https://github.com/tsoding)
    3. [ ] Implement async behavior in C with epoll
6. [ ] Properly respond with file size in order to sustain the connection
7. [ ] Implement custom allocator ([arena/region](https://en.wikipedia.org/wiki/Region-based_memory_management) allocator using either bump/linear or chunk)

