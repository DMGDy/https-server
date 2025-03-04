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
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_PORT 8000
#define MAX_CLIENT 8
//16kb
#define BODY_LEN 16384
//4kb
#define HEADER_LEN 4096

typedef enum
{
  ERROR = -1,
  REQ,
  PATH,
  VERSION,
  DONE,
} req_line_fsm;

typedef enum 
{
  REQUEST_LINE, // obtain request type, should be first
  ATTR, // User-Agent, Accept, Connection
  VAL, // ie. Mozilla 5.0..., text/html, keep-alive,
  VALS // if comma seperated ie. text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
} header_parse_fsm;

// supported headers, any others will return a 404
typedef enum {
  NOT_SUPPORTED = -1,
  // only GET for now
  GET,
} request_t;

typedef enum 
{
  SCANNING,
  CR,
  LF,
  FOUND
} HTTP_CRLF_fsm;

typedef struct request_line
{
  request_t request;
  char* path;
  char* version;
} request_line_t;

typedef struct header_info
{
  request_line_t request_line;
  char* connection;
  char* user_agent;
  char** accept_mime;
} header_info_t;

// for each connection
typedef struct connect_args
{
  int client_fd;
  void* client_addr;
  socklen_t caddr_len;
} connect_args_t;

static const char* header_fields[] = {"User-Agent", "Accept", "Connection"};
static const size_t header_fields_len = 3;

static const char* allowed_rqs[] = {"GET"}; // Only GET for now
static const size_t allowed_reqs_len = 1;

static const char* allowed_paths[] = {"/", "/index.html", "index.html", "/styles.css", "styles.css"};
static const size_t allowed_paths_len = 5;

char* strdup(const char* s);
void client_connect(void* args);
void read_header(char* buff,int client);
int is_complete_header(char* buff, int n);
header_info_t* parse_header(char* buff);
int is_header_field(char* field);
request_t is_allowed_req(char* field);
request_line_t parse_req_line(char* line);

// since C11 does not have strdup
char*
strdup(const char* src)
{
  // include '\0'
  size_t n = strlen(src) + 1;

  // should not be larger than 128
  if (src == NULL || n > 128)
    {
      return NULL;
    }

  char* dest = malloc(n);

  if(dest == NULL)
    {
      return NULL;
    }

  return memcpy(dest,src,n);



}

request_line_t
parse_req_line(char* line)
{
  request_line_t req_line;
  
  // first line info deliminated by space
  // GET / HTTP/1.1
  // REQ PATH VERSION
  char* tok = strtok(line, " ");
  req_line_fsm state =  REQ;

  do
    {
      req_line_fsm nstate = ERROR;
      switch(state)
        {
          case(ERROR):
              puts("ERROR");
              return req_line;
            break;
          case(REQ):
            {
              request_t req = is_allowed_req(tok);
              req_line.request = req;        
              if(!(req < 0))
                {
                  nstate = PATH;
                }
              else
                {
                  nstate = ERROR;   
                }
              break;
            }
          case(PATH):
            {
              char* path = malloc(strlen(tok));
              if(path)
                {
                  memcpy(path, tok, strlen(tok));
                }
              req_line.path = path;
              nstate = VERSION;
              break;
            }
          case(VERSION):
            {
              char* ver = malloc(strlen(tok));
              if(ver)
                {
                  memcpy(ver, tok, strlen(tok));
                }
              req_line.version= ver;
              nstate = DONE;
              break;
            }
          // should have exited by now but just to be sure i dont process garbage
          case(DONE): 
            return req_line;
        }
      tok = strtok(NULL, " ");
      state = nstate;
    }
  while(tok);

  return req_line;
}

// return index of request type, otherwise, -1 of not allowed
request_t
is_allowed_req(char* req)
{
  int pos = -1;
  for(size_t i = 0; i < allowed_reqs_len; ++i)
    {
      if(strcmp(req,allowed_rqs[i]) == 0)
        {
          pos = i;
          break;
        }
    }
  return (request_t)pos;
}


// return index of header_field or -1 if none
int
is_header_field(char* field)
{
  int pos = -1;
  if(!field)
    {
      return pos;
    }
  for(size_t i = 0; i < header_fields_len; ++i)
    {
      if(strcmp(field,header_fields[i]) == 0)
        {
          pos = i;
          break;
        }
    }
  return pos;
}

header_info_t*
parse_header(char* buff)
{
  header_info_t* header_info = malloc(sizeof(header_info_t));

  char* line = strtok(buff,"\n");

  header_info->accept_mime = malloc(sizeof(char*));

  header_parse_fsm state = REQUEST_LINE;
  header_parse_fsm nstate = REQUEST_LINE;
  char* save;
  char* field = "";
  char* val = "";
  puts("");
  while(line && val && field)
    {
      switch(state)
        {
          case(REQUEST_LINE):
            {
              // offset current line + 1(delim) to proceed to next line
              save = line + strlen(line) + 1;
              char* line_cpy = malloc(strlen(line));
              memcpy(line_cpy, line, strlen(line));

              header_info->request_line = parse_req_line(line_cpy);
              free(line_cpy);
              nstate = ATTR;

              break;
            }
          case(ATTR):
            {
              
              // check to make sure they are not NULL (end of request)
              line  = (save)? strtok(save,"\n"): NULL;
              save = (line)? line + strlen(line) + 1: NULL;
              field = (line)? strtok(line,": "): NULL;

              if(is_header_field(line) >= 0)
                {
                  printf("%s\n",field);
                  nstate = VAL;
                }
              break;
            }
          case(VAL):
            {
              // parse content after : 
              val = strtok(NULL,": ");
              printf("%s\n\n",val);
              nstate = ATTR;

              if(strncmp("Accept",field,7) == 0)
                {
                  nstate = VALS;
                }
              else if(strncmp("Connection",field,11) == 0)
                {

                }
              else if(strncmp("User-Agent",field,11) == 0)
                {

                }

              break;
            }

          case(VALS):
            {
              // get information seperated by commas
              char* info = strtok(val,",");

              
              size_t i = 0;
              do
                {
                  header_info->accept_mime = realloc(header_info->accept_mime, 
                                                 (i+1)*sizeof(char*));
                  header_info->accept_mime[i] = strdup(info);
                  info = strtok(NULL,",");
                  i++;
                }
              while(info);
              header_info->accept_mime[i] = NULL;
              nstate = ATTR;
            }
        }
      state = nstate;
    }
  puts("done");

  return header_info;
}

//return the first position of CRLF, otherwise return -1
int
is_complete_header(char* buff, int n)
{
  HTTP_CRLF_fsm state = SCANNING;
  int position = -1;
  int cr_ctr = 0;
  int lf_ctr = 0;
  for(int i = 0; i < n; ++i)
    {
      HTTP_CRLF_fsm nstate = SCANNING;
      char c = buff[i];

      switch(state)
        {
          case(SCANNING):
            if(c == '\r')   
              {
                nstate = CR;
                cr_ctr++;
              } 
            else 
              {
                nstate = SCANNING;
              }
            break;
          case(CR):
            if(c == '\n' && (cr_ctr == 2 && lf_ctr == 1)) 
              {
                // \r\n\r\n
                // *     ^  3 positions away from current index 
                position = i - 3;
                nstate = FOUND;
              } 
            else if (c == '\n')
              {
                nstate = LF;
                lf_ctr++;
              } 
            else 
              {
                nstate = SCANNING;
                cr_ctr = 0;
                lf_ctr = 0;
              }
            break;
          case(LF):
            if (c == '\r' && (cr_ctr == 1 && lf_ctr == 1)) 
              {
                nstate = CR;
                cr_ctr++;
              }
            else 
              {
                nstate = SCANNING;
                cr_ctr = 0;
                lf_ctr = 0;
              }
            break;
          case(FOUND):
            return position;
        }

      state = nstate;
    }

  return position;
}

// fill buff* with header information
void 
read_header(char* buff,int client) 
{
  int complete = 0;
  size_t offset = 0;
  do 
    {
      size_t n = recv(client, buff+offset, HEADER_LEN-offset, 0);
      // pos is the bytes up to CRLF
      int pos = is_complete_header(buff,(int)n);
      if (pos > 0) 
        {
          buff[pos] = '\0';
          complete = 1;
        } 
      else 
        {
          offset += n;
        }
    } 
  while(!complete);
}


void
client_connect(void* args) 
{
  connect_args_t* connect_args = (connect_args_t*)args;

  // get client ip
  char ip_inet_str[INET_ADDRSTRLEN] = {0};
  char ip_inet6_str[INET6_ADDRSTRLEN] = {0};

  inet_ntop(AF_INET,
      connect_args->client_addr,
      ip_inet_str,
      connect_args->caddr_len);

  inet_ntop(AF_INET6,
      connect_args->client_addr,
      ip_inet6_str,
      connect_args->caddr_len);

  printf("\nNew connection to\n\tIPv4: %s\n\tIPv6: %s\n",
      ip_inet_str,
      ip_inet6_str);

  // read header
  char* header_buff = realloc(NULL,HEADER_LEN);
  // header_buff to contain header string, terminated with \0
  read_header(header_buff,connect_args->client_fd);
  printf("%s\n",header_buff);
  // parse information we care about in the header
  header_info_t* info = parse_header(header_buff);

}

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


  int sock_fd = socket(AF_INET6, SOCK_STREAM, 0);

  int set = 1;
  if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) == -1)
    {
      perror("Error assigning socket options: ");
      return EXIT_FAILURE;
    }

  int unset = 0;
  if(setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &unset, sizeof(unset)) == -1)
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

      struct sockaddr_in6 client_addr;


      int caddr_len = sizeof(client_addr);
      int client = accept(sock_fd, 
          (struct sockaddr*)&client_addr,
          (socklen_t*)&caddr_len);
      puts("attempting to connect");
      if(client == -1)
        {
          perror("Error connecting to client: ");
          close(sock_fd);
          return EXIT_FAILURE;
        }

      connect_args_t args = {
        client,     
        (void*)&client_addr,
        (socklen_t)caddr_len
      };

      client_connect((void*)&args);

    }

  return 0;
}
