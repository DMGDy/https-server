#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_PORT 8080
#define MAX_CLIENT 8

int
main(void)
{
  // ipv6
  struct sockaddr_in6 addr = 
  {
    AF_INET6,
    htons(SERVER_PORT),
    0,
    in6addr_any,
    0,
  };

  struct sockaddr_in6 client_addr;

  int sock_fd = socket(AF_INET6, SOCK_STREAM, 0);

  int flag = 1;
  if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
  {
    perror("Error assigning socket options: ");
    return EXIT_FAILURE;
  }

  if(bind(sock_fd,(struct sockaddr*)&addr, (socklen_t)sizeof(addr)) == -1)
  {
    perror("Error connecting to socket: ");
    return EXIT_FAILURE;
  }

  if(listen(sock_fd, MAX_CLIENT) == -1)
  {
    perror("Error listening: ");
    return EXIT_FAILURE;
  }

  puts("Listening for any new connections ");
  while(1)
  {
    int client = accept(sock_fd, 
        (struct sockaddr*)&client_addr,
        (socklen_t*) sizeof(client_addr));

    if(client == -1)
    {
      perror("Error connecting to client: ");
      return EXIT_FAILURE;
    }

  }

  printf("Hello, World!\n");
  return 0;
}
