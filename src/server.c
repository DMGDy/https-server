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
