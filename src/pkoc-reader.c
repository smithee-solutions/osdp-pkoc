/*
  pkoc-reader - perform smartcard actions for PKOC OSDP ACU Operations
*/

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <pkoc-osdp.h>
#include <pkoc-osdp-version.h>

int longindex;
PKOC_CONTEXT my_context;
char optstring [1024];
struct option longopts [] = 
{
  {"help", 0, &(my_context.action), PKOC_SWITCH_HELP},
  {"request-auth", 0, &(my_context.action), PKOC_SWITCH_REQ_AUTH},
  {0, 0, 0, 0}
};
int status_opt;
  

int main
  (int argc,
  char *argv [])

{ /* main for pkoc-reader */

  PKOC_CONTEXT *ctx;
  char my_oui_string [1024];
  OSDP_MULTIPART_HEADER my_payload_header;
  char my_payload_hex_string [1024];
  unsigned char my_response_id;
  char osdp_directive [8192];
  char tstring [3072];
  int status;


  status = ST_OK;
  ctx = &my_context;
  ctx->log = stderr;

  fprintf(stderr, "pkoc-reader smartcard interface %s\n", PKOC_OSDP_VERSION);
  strcpy(my_oui_string, PKOC_OUI_STRING);
  my_response_id = OSDP_PKOC_CARD_PRESENT;

  my_payload_hex_string [0] = 0;
  my_payload_header.offset = 0;
  my_payload_header.fragment_length = 10;
  my_payload_header.total_length = my_payload_header.fragment_length;
  strcpy(tstring, mph_in_hex(&my_payload_header));
  strcat(my_payload_hex_string, tstring);

  // response payload is
  // supported protocol version 5C 02 01 00
  // transaction sequence FD 01 00
  // error tlv FB 01 00

  strcpy(tstring, "5C020100FD0100FB0100");
  strcat(my_payload_hex_string, tstring);

/*
  initiate pcsc communications with card
  form mfgrep
  send mfgrep via osdp
*/

  if (status EQUALS ST_OK)
  {
    sprintf(osdp_directive,
"{\"command\":\"mfgrep\",\"oui\":\"%s\",\"response-id\":\"%02X\",\"response-specific-data\":\"%s\"}\n",
    my_oui_string, my_response_id, my_payload_hex_string);
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "DEBUG: directive is: %s\n", osdp_directive);
    status = send_osdp_command(ctx, "/opt/osdp-conformance/run/PD/open-osdp-control", osdp_directive);
  };
  return(status);
}
  

int pkoc_switches
  (PKOC_CONTEXT *ctx,
  int *command,
  int argc,
  char *argv [])

{ /* pkoc_switches */

  int done;
  int status;


  status = ST_OK;
  done = 0;
  while (!done)
  {
    status_opt = getopt_long(argc, argv, optstring, longopts, &longindex);
    switch(ctx->action)
    {
    case PKOC_SWITCH_REQ_AUTH:
      fprintf(stderr, "read a card.\n");
      status = ST_OK;
    case PKOC_SWITCH_HELP:
      fprintf(stderr, "--help - display this help text.\n");
      fprintf(stderr, "--request-auth - request card authenticate\n");
      status = ST_OK;
      break;
    default:
      status = ST_PKOC_UNKNOWN_SWITCH;
      break;
    };
  };
  return(status);

} /* pkoc_switches */

