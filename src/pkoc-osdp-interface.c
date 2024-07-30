#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>


#include <pkoc-osdp.h>


int
  send_osdp_command
    (PKOC_CONTEXT *ctx,
    char *destination,
    char *command_string)

{ /* send_osdp_command */

  struct sockaddr_un addr;
  int fd;
  int rc;
  char socket_path [1024];
  int status;


  status = ST_OK;
  fd = -1;
  if (ctx->verbosity > 3)
  {
    fprintf(ctx->log, "DEBUG: sending command %s\n", command_string);
    fflush(ctx->log);
  };
  if (strlen(destination) EQUALS 0)
    sprintf (socket_path, "/opt/osdp-conformance/run/ACU/open-osdp-control");
  else
    strcpy(socket_path, destination);
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
  {
    status = -246;
  };
  if (status EQUALS ST_OK)
  {
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    {
      status = ST_PKOC_OSDP_MISSING;
    };

    if (status EQUALS ST_OK)
    {
      rc = strlen(command_string);

      if (write(fd, command_string, rc) != rc)
      {
        status = -265;
      }
    }
  };
  if (fd != -1)
    close(fd);
  return(status);

} /* send_osdp_command */

