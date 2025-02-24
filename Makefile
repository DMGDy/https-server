CC=gcc
#CFLAGS=-Wall -Wextra -Werror -Wpedantic -std=c11
CFLAGS=-Wall -Wextra -Wpedantic -std=c11

.PHONY: all
all: server

server: 
	$(CC) $(CFLAGS) src/server.c -o bin/server

.PHONY: clean
clean:
	rm -f bin/*
