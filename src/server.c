/* https-server
 * Copyright (C) 2025 Dylan Dy <dylangarza1909@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
    close(sock_fd);
    return EXIT_FAILURE;
  }

  if(listen(sock_fd, MAX_CLIENT) == -1)
  {
    perror("Error listening: ");
    close(sock_fd);
    return EXIT_FAILURE;
  }

  puts("Listening for any new connections ");
  while(1)
  {
    int caddr_len = sizeof(client_addr);
    int client = accept(sock_fd, 
        (struct sockaddr*)&client_addr,
        (socklen_t*)&caddr_len);

    if(client == -1)
    {
      perror("Error connecting to client: ");
      close(sock_fd);
      return EXIT_FAILURE;
    }

    char ip_inet_str[INET_ADDRSTRLEN] = {0};
    char ip_inet6_str[INET6_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET,
        (void*)&client_addr,
        ip_inet_str,
        (socklen_t)caddr_len);

    inet_ntop(AF_INET6,
        (void*)&client_addr,
        ip_inet6_str,
        (socklen_t)caddr_len);

    printf("\nNew connection to\n\tIPv4: %s\n\tIPv6: %s\n",
        ip_inet_str,
        ip_inet6_str);
    
  }

  printf("Hello, World!\n");
  return 0;
}
