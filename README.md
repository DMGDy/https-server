# Dual-stack HTTP(S) server 

An HTTP server. I will see how far I can go with its use case. 
Potentially can replace [apache](https://httpd.apache.org/) on my personal website.
Would need to do many things for that to work.

## Building
This project uses [tsodings](https://github.com/tsoding) 
[nob.h](https://github.com/tsoding/nob.h/) for building.


Simply run `cc -o nob nob.c` and the binary will build as
`bin/server`


## TO-DO
I hopefully can get through most of these. Ordered in what I think in the moment
is the primary features I need working first. Will update as I find out more specifics.

1. [X] Parse HTTP Request and deliver HTML
    1. [X] Send files beyond index.html
2. [X] Add SSL/TLS encryption with openssl
3. [ ] Add concurrency
    1. [ ] Multi-thread for multiple connections (maybe thread pool or semaphore approach)
    2. [ ] Potentially move to C [coroutines](https://github.com/tsoding/coroutines). 
    Written by [tsoding](https://github.com/tsoding)
