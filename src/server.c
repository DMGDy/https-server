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
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>

#include <openssl/ssl.h>

#include "config.h"

//16kb
#define BODY_LEN 16384
//4kb
#define HEADER_LEN 4096
// count of files that can be sent
#define FILE_BUFF_LEN 8192
// max wait time before server disconnects from client
#define TIMEOUT_DURATION 100000

typedef enum req_line_fsm
{
  ERROR = -1,
  REQ,
  PATH,
  VERSION,
  DONE,
} req_line_fsm;

typedef enum header_parse_fsm
{
  FAILURE = -1,
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

// since operations are not guaranteed to finish
// and i cannot block I/O need to keep track of state
typedef enum
{
  TLS_HANDSHAKE,
  READ_REQUEST,
  WRITE_RESPONSE,
  CLOSE_CONNECTION
}connect_state_t;

typedef struct request_line
{
  char* version;
  int path;
  int error;
  request_t request;
} request_line_t;

typedef struct header_info
{
  request_line_t request_line;
  char* connection;
  char* accept_mime;
} header_info_t;

// for each connection
typedef struct connect_args
{
  header_info_t* header_info;
  SSL* ssl;
  void* client_addr;
  char* rbuffer;
  char* wbuffer;
  size_t read_size;
  size_t write_size;
  socklen_t caddr_len;
  int client_fd;
  connect_state_t state;
  bool done_reading;
  bool done_writing;
  bool read_and_write;
} connect_args_t;

static const char* header_fields[] = {"Accept", "Connection"};
static const size_t header_fields_len = 2;

static const char* allowed_rqs[] = {"GET"}; // Only GET for now
static const size_t allowed_reqs_len = 1;

// all files that can be sent 
static const char hostname[] = "dylxndy.xyz/";

volatile sig_atomic_t shutdown_flag = 0;

void send_response(SSL* ssl, header_info_t* header_info);
char* strdup(const char* s);
int client_connect(void* args);
int read_request(SSL* ssl, char* buff, size_t* offset, bool* complete);
int is_complete_header(char* buff, int n);
header_info_t* parse_header(char* buff);
int is_header_field(char* field);
int is_image(int pos);
request_t is_allowed_req(char* field);
int get_req_file(char* requested);
void sig_handler(int sig);
void setnonblocking(int fd);

void setnonblocking(int sock) {
  int opt;

  opt = fcntl(sock, F_GETFL);
  if (opt < 0) 
    {
      perror("fcntl(F_GETFL) fail.");
      exit(EXIT_FAILURE);
    }
  opt |= O_NONBLOCK;
  if (fcntl(sock, F_SETFL, opt) < 0) 
    {
      perror("fcntl(F_SETFL) fail.");
      exit(EXIT_FAILURE);
    }
}


void
sig_handler(int sig)
{
  if (sig == SIGINT || SIGKILL)
    {
      shutdown_flag = 1;
    }
}

void
send_response(SSL* ssl, header_info_t* header_info)
{
  FILE* file;
  int file_index = (header_info != NULL)? header_info->request_line.path: 0;
  file_index = (file_index == 1)? 2: file_index;

  // webpage and related files as subdirectory
  size_t path_len = strlen(hostname) + strlen(allowed_files[file_index]);
  char* path = malloc(path_len + 1);
  strcpy(path, hostname);
  strcpy(path+strlen(hostname),allowed_files[file_index]);
  path[path_len] = 0;

  // file size for response
  long sz = 0;

  // open requested file
  if (!(file = fopen(path, "rb"))) 
    {
      perror("Error opening");
      free(path);
      return;
    }
  free(path);
  // get file size by seeking to end
  fseek(file, 0L, SEEK_END);
  sz = ftell(file);

  rewind(file);
  // construct response header
  char response[HEADER_LEN] = {0};

  if (file_index != 0)
    {
      sprintf(response,
          "HTTP/1.1 200 OK\n"
          "Server: epic-server v420.69(Linux)\n"
          "Accept-Ranges: bytes\n"
          "Connection: keep-alive\n"
          "Content-Type: %s\n"
          "Content-Length: %ld"
          "\r\n\r\n",
          header_info->accept_mime,
          sz
          );
    }
  else 
    {
      sprintf(response,
          "HTTP/1.1 400 Error\n"
          "Server: epic-server v420.69 (Chad Linux)\n"
          "Accept-Ranges: bytes\n"
          "Connection: keep-alive\n"
          "Content-Type: text/html"
          "\r\n\r\n"
          );
    }

  printf("%s\n",response);

  SSL_write(ssl, response, strlen(response));

  char file_buff[FILE_BUFF_LEN] = {0};
  size_t n = 0;
  size_t sent = 0;
  while((n = fread(file_buff, 1, sizeof(file_buff),file)) > 0)
    {
      size_t bytes = 0;
      if ((bytes = SSL_write(ssl, file_buff, n)) != n)
        {
          perror("Error error sending file");
        }
      sent+=bytes;
    }

  printf("\n\nbytes sent: %zd\n\n", sent);
  fclose(file);
}

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

  if (dest == NULL)
    {
      return NULL;
    }

  return strncpy(dest,src,n);

}

// return index of what file was requested, if nothing, send error.html
int
get_req_file(char* requested)
{
  if (requested == NULL)
    {
      return 0;
    }
  for(int i = 1; i < ALLOWED_FILES; ++i)
    {
      // discard first '/'
      if (strcmp(requested+1, allowed_files[i]) == 0)
        {
          return i;
        }
    }
  puts("File not found");

  return 0;
}

request_line_t
parse_req_line(char* line)
{
  request_line_t req_line;
  req_line.error = 0;
  
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
              req_line.error = 1;
              return req_line;
            break;
          case(REQ):
            {
              request_t req = is_allowed_req(tok);
              req_line.request = req;        
              if (!(req < 0))
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
              char* path = strdup(tok);

              req_line.path = get_req_file(path);
              free(path);
              nstate = VERSION;
              break;
            }
          case(VERSION):
            {
              char* ver = strdup(tok);
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

// return 0 if 'pos' provides a file of an image type
int
is_image(int pos)
{
  size_t len = strlen(allowed_files[pos]);


  //"assets/buttons/agplv3.png",
  //                       ^  
  if (strcmp(allowed_files[pos]+(len-3),"gif") == 0||
      strcmp(allowed_files[pos]+(len-3),"ico") == 0||
      strcmp(allowed_files[pos]+(len-3),"png") == 0)
    {
      return 0;
    }
  return 1;
}

// return index of request type, otherwise, -1 of not allowed
request_t
is_allowed_req(char* req)
{
  int pos = -1;
  for(size_t i = 0; i < allowed_reqs_len; ++i)
    {
      if (strcmp(req,allowed_rqs[i]) == 0)
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
  if (!field)
    {
      return pos;
    }
  for(size_t i = 0; i < header_fields_len; ++i)
    {
      if (strcmp(field,header_fields[i]) == 0)
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

  header_parse_fsm state = REQUEST_LINE;
  header_parse_fsm nstate = REQUEST_LINE;
  char* save = "";
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
              char* line_cpy = malloc(strlen(line) + 1);
              strncpy(line_cpy, line, strlen(line));
              line_cpy[strlen(line)] = 0;

              header_info->request_line = parse_req_line(line_cpy);
              free(line_cpy);

              if (header_info->request_line.error)
                {
                  nstate = FAILURE;
                }
              else
                {
                  nstate = ATTR;
                }
              break;
            }
          case(ATTR):
            {
              // check to make sure they are not NULL (end of request)
              line  = (save && (strlen(save) > 0))? strtok(save,"\n"): NULL;
              save = (line)? line + strlen(line) + 1: NULL;
              field = (line)? strtok(line,": "): NULL;

              if (is_header_field(line) >= 0)
                {
                  nstate = VAL;
                }
              break;
            }
          case(VAL):
            {
              // parse content after : 
              val = strtok(NULL,": ");
              nstate = ATTR;

              if (strcmp("Accept",field) == 0)
                {
                  nstate = VALS;
                }
              else if (strcmp("Connection",field) == 0)
                {
                  header_info->connection = strdup(val);
                }
              break;
            }

          case(VALS):
            {
              // get the first accepted type
              char* info = strtok(val,",");
              // need to determine what type of image file
              // replace avif in 'image/avif'
              // favicon.ico == image/x-icon
              // *.png == image/png
              // *.gif == image/gif
              int af_pos = header_info->request_line.path;
              if (is_image(af_pos) == 0)
                {
                  char actual_type[16] = "image/";   
                  size_t len = strlen(allowed_files[af_pos]);

                  if (strcmp(allowed_files[af_pos]+(len-3), "ico") == 0)
                    {

                      strcpy(actual_type+6,"x-icon");
                    }
                  else
                    {
                      strcpy(actual_type+6,allowed_files[af_pos]+(len-3));
                    }

                  header_info->accept_mime = strdup(actual_type);

                }
              else
                {
                  header_info->accept_mime = strdup(info);
                }

              nstate = ATTR;
              break;
            }
          case(FAILURE):
            {
              return NULL;
            }
        }
      state = nstate;
    }

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
            if (c == '\r')   
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
            if (c == '\n' && (cr_ctr == 2 && lf_ctr == 1)) 
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
int 
read_request(SSL* ssl, char* buff, size_t* offset, bool* complete) 
{
  size_t timeout = 0;
  do 
    {
      int n = SSL_read(ssl, buff+*offset, HEADER_LEN-*offset);
      int err = SSL_get_error(ssl, n);
      // if receiving nothing for a while, return -1 to end connection
      switch(err)
        {
          // probably done reading
          case SSL_ERROR_NONE:
            {
              *complete = true;
              *offset += n;
              break;
            }
          // not done reading yet
          case SSL_ERROR_WANT_READ:
            {
              *offset += n;
              break;
            }
          //something bad, timeout if it keeps happening
          default:
            timeout++;
        }
      if (timeout >= TIMEOUT_DURATION)
        {
          return -1;
        }
      // pos is the bytes up to CRLF
    } 
  while(!*complete);

  return 0;
}

int
client_connect(void* vargs) 
{
  connect_args_t* args = (connect_args_t*)vargs;
  int keep_alive = 0;

  connect_state_t* state = &args->state;
  connect_state_t next_state = *state;
  SSL* ssl = args->ssl;

  switch(*state)
    {
      case TLS_HANDSHAKE:
        {
          puts("TLS Handshake in progress...");
          int ret = SSL_accept(ssl);
          int err = SSL_get_error(ssl,ret);
          if (err != SSL_ERROR_NONE)
            {
              switch(err)
                {
                  case SSL_ERROR_WANT_READ:
                  case SSL_ERROR_WANT_ACCEPT:
                  case SSL_ERROR_WANT_CONNECT:
                  case SSL_ERROR_WANT_WRITE:
                    {
                      next_state = TLS_HANDSHAKE;
                      break;
                    }
                  default:
                    fprintf(stderr,"%d Error during TLS handshake with code %d\n",ret, err);
                    break;
                }
            }
          else
            {
              puts("TLS handshake accepted");
              next_state = READ_REQUEST;
            }
          break;
        }
      case READ_REQUEST:
        {
          puts("now reading");
          char* rbuffer = args->rbuffer;
          rbuffer = NULL;
          rbuffer = malloc(HEADER_LEN);
          // cheeky way to exit in one line
          (!rbuffer)? (exit(EXIT_FAILURE),1): 0;
          // continue reading
          if (!args->done_reading)
            {
              int ret = read_request(ssl, rbuffer, &args->read_size, &args->done_reading);
              if (ret > 0)
                {
                  return 1;
                }
              int pos = is_complete_header(rbuffer,args->read_size);
              if (pos <= 0)
                {
                  printf("%s\n",rbuffer);
                  fprintf(stderr,"Error parsing header file\n");
                  return 1;
                }
              rbuffer[pos] = '\0';
            }
          // parse through (cant have else otherwise it will skip if 
          // read call finishes)
          if (args->done_reading)
            {
              printf("%s",rbuffer);
              args->header_info = parse_header(rbuffer);
              puts("");
              next_state = WRITE_RESPONSE;
            }
          if(args->read_and_write)
            {
              goto write;
            }
          break;
        }
      case WRITE_RESPONSE:
        {
write:
          send_response(args->ssl, args->header_info);
//          SSL_free(args->ssl);
//
          args->rbuffer = 0;
          args->done_reading = 0;
          args->read_size = 0;
          free(args->header_info->connection);
          free(args->header_info->accept_mime);
          free(args->header_info->request_line.version);
          free(args->header_info);
//          free(args->rbuffer);
          next_state = READ_REQUEST;
          break;
        }
      case CLOSE_CONNECTION:
        {
          return 0;         
          break;
        }
    }


  printf("%d - > %d\n",(int)(*state), (int)next_state);
  *state = next_state;
  /*
  // read header
  char* header_buff = malloc(HEADER_LEN);
  // header_buff to contain header string, terminated with \0
  keep_alive = read_header(connect_args->ssl, header_buff);
  printf("%s\n",header_buff);
  if (keep_alive == 0)
  {

    // parse information we care about in the header
    header_info_t* header_info = parse_header(header_buff);

    send_response(connect_args->ssl, header_info);

    free(header_buff);

    free(header_info->connection);
    free(header_info->accept_mime);
    free(header_info->request_line.version);
    free(header_info);
  }
    */


  return 0;
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

  int listen_sock = socket(AF_INET6,SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

  int set = 1;
  if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) == -1)
    {
      perror("Error assigning socket options");
      return EXIT_FAILURE;
    }

  int unset = 0;
  if (setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &unset, sizeof(unset)) == -1)
    {
      perror("Error assigning socket options");
      return EXIT_FAILURE;
    }

  if (bind(listen_sock,(struct sockaddr*)&addr, (socklen_t)sizeof(addr)) == -1)
    {
      perror("Error connecting to socket");
      close(listen_sock);
      return EXIT_FAILURE;
    }

  if (listen(listen_sock, MAX_CLIENT) == -1)
    {
      perror("Error listening");
      close(listen_sock);
      return EXIT_FAILURE;
    }

  // ev is for main socket, events for client sockets
  struct epoll_event ev, events[MAX_CLIENT];
  ev.events = EPOLLIN;
  // listen to socket that will have new client sockets
  ev.data.fd = listen_sock;
  int epollfd = epoll_create1(0);

  if (epollfd == -1)
    {
      perror("Error creating epoll fd");
      return EXIT_FAILURE;
    }

  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1)
    {
      perror("Error adding socket listen_sock for epoll");
      return EXIT_FAILURE;
    }
  // number of fds that are ready
  ssize_t n_fds = 0;

  // set up SSL context
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());

  puts("Listening for any new connections ");
  // for graceful shutdown_flag
  signal(SIGINT, sig_handler);

  while(!shutdown_flag)
    {

      // add any new connections to events
      n_fds = epoll_wait(epollfd, events, MAX_CLIENT, -1);
      if (n_fds == -1)
        {
          perror("Error polling for events on epollfd");
          return EXIT_FAILURE;
        }
      // for each new connection
      for(ssize_t n = 0; n < n_fds; ++n)
        {
          if (events[n].data.fd == listen_sock)
            {
              struct sockaddr_in6 client_addr;

              int caddr_len = sizeof(client_addr);

              puts("TCP Handshake");
              int client = accept(listen_sock, 
                  (struct sockaddr*)&client_addr,
                  (socklen_t*)&caddr_len);

              if (client == -1 && shutdown_flag)
                {
                  continue;
                }
              else if (client == - 1 && !shutdown_flag)
                {
                  perror("Error connecting to client");
                  continue;
                }

              // get client ip
              char ip_inet6_str[INET6_ADDRSTRLEN] = {0};

              inet_ntop(AF_INET6,
                  &client_addr.sin6_addr,
                  ip_inet6_str,
                  INET6_ADDRSTRLEN);

              printf("\nNew connection to \n\tIPv6: %s\n",
                  ip_inet6_str);

              setnonblocking(client);

              SSL* ssl = SSL_new(ctx);
              if (!ssl)
                {
                  perror("Error establishing TLS connection");
                  goto error;
                }

              SSL_set_fd(ssl, client);

              if (SSL_use_certificate_file(ssl, SSL_CERT_FILE, SSL_FILETYPE_PEM) != 1)
                {
                  perror("Error loading certificate");
                  goto error;
                }

              if (SSL_use_PrivateKey_file(ssl, SSL_KEY_FILE, SSL_FILETYPE_PEM) != 1)
                {
                  perror("Error loading private key");
                  goto error;
                }


              ev.events = EPOLLIN | EPOLLOUT | EPOLLET;

              connect_args_t* args = malloc(sizeof(connect_args_t));

              // looks awful but you can always scroll to the top
              *args = (connect_args_t) {
                NULL,
                ssl,
                (void*)&client_addr,
                NULL,
                NULL,
                0,
                0,
                (socklen_t)caddr_len,
                client,
                TLS_HANDSHAKE,
                false,
                false,
                false
              };

              ev.data.ptr = args;

              if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client, &ev) == -1)
                {
                  perror("Error adding client socket to interest list");
                  return EXIT_FAILURE;
                }
              continue;
              //client_connect(ssl,(void*)&args);
error:
              if (client != -1)
                {
                  close(client);
                  continue;
                }
              SSL_free(ssl);

            }
          else
            {
              void* args = events[n].data.ptr;
              if (args == NULL)
                {
                  perror("Massive");
                  exit(EXIT_FAILURE);
                }
              if(events[n].events == 5)
                {
                  puts("both");
                  ((connect_args_t*)args)->read_and_write = true;
                }
              puts("going in");
              client_connect(args);
            }
        }
    }

  close(listen_sock);
  SSL_CTX_free(ctx);

  return 0;
}
