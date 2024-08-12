/*
  pkoc-reader - perform smartcard actions for PKOC OSDP ACU Operations

  Usage:

    pkoc-reader --card-present - check for a card and if found report
      card-present to the ACU

    pkoc-reader --auth-request - given auth request from ACU do auth request to card.  Assumes card is still present.
*/

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <pkoc-osdp.h>
#include <pkoc-osdp-version.h>

int pkoc_switches(PKOC_CONTEXT *ctx, int *command, int argc, char *argv []);
PKOC_CONTEXT my_context; // up here to support longopts initialization
int longindex;
char optstring [1024];
struct option longopts [] = 
{
  {"auth-request", 0, &(my_context.action), PKOC_SWITCH_AUTH_REQUEST},
  {"card-present", 0, &(my_context.action), PKOC_SWITCH_CARD_PRESENT},
  {"help", 0, &(my_context.action), PKOC_SWITCH_HELP},
  {0, 0, 0, 0}
};
int status_opt;
  

int main
  (int argc,
  char *argv [])

{ /* main for pkoc-reader */

  int command;
  PKOC_CONTEXT *ctx;
  char my_oui_string [1024];
  OSDP_MULTIPART_HEADER my_payload_header;
  char my_payload_hex_string [1024];
  unsigned char my_response_id;
  char osdp_directive [8192];
  int send_response;
  char tstring [3072];
  int status;


  status = ST_OK;
  ctx = &my_context;
  ctx->log = stderr;
  status = get_pkoc_settings(ctx);
  if (status EQUALS ST_OK)
    status = get_pkoc_state(ctx);
  send_response = 0;

  fprintf(stderr, "pkoc-reader smartcard interface %s\n", PKOC_OSDP_VERSION);
  status = pkoc_switches(ctx, &command, argc, argv);

  switch(command)
  {
  default:
    fprintf(stderr, "Unknown command (%d.)\n", command);
    break;

  case PKOC_SWITCH_AUTH_REQUEST:
    fprintf(stderr, "Authentication Requested\n");
    status = init_smartcard(ctx);
    if (status EQUALS ST_OK)
    {
fprintf(stderr, "DEBUG: protocol version etc to context\n");
      status = pkoc_card_auth_request(ctx);
    };
    if (status EQUALS ST_OK)
    {
fprintf(stderr, "DEBUG: auth request ok\n");
    };
    break;

  case PKOC_SWITCH_CARD_PRESENT:
    status = init_smartcard(ctx);
    if (status EQUALS ST_OK)
    {
      if (ctx->verbosity > 3)
        fprintf(stderr, "pkoc-reader: Card was accessed.\n");
      strcpy(my_oui_string, PKOC_OUI_STRING);
      my_response_id = OSDP_PKOC_CARD_PRESENT;

    // response payload is
    // supported protocol version 5C 02 01 00
    // transaction sequence FD 01 00
    // error tlv FB 01 00
    my_payload_hex_string [0] = 0;
    my_payload_header.offset = 0;
    my_payload_header.fragment_length = 10;
    my_payload_header.total_length = my_payload_header.fragment_length;
    strcpy(tstring, mph_in_hex(&my_payload_header));
    strcat(my_payload_hex_string, tstring);

    strcpy(tstring, "5C02");
    strcat(my_payload_hex_string, tstring);
    sprintf(tstring, "%02X%02X", ctx->protocol_version [0], ctx->protocol_version [1]);
    strcat(my_payload_hex_string, tstring);
    strcpy(tstring, "FD0100FB0100");
    strcat(my_payload_hex_string, tstring);
    send_response = 1;
    };
    break;

  case PKOC_SWITCH_NEXT_TRANSACTION:
    fprintf(stderr, "ACU reports ready for PKOC operation.\n");
    break;
  };

  /*
    form mfgrep
    send mfgrep via osdp
  */
  if ((status EQUALS ST_OK) && (send_response))
  {
    sprintf(osdp_directive,
"{\"command\":\"mfgrep\",\"oui\":\"%s\",\"response-id\":\"%02X\",\"response-specific-data\":\"%s\"}\n",
    my_oui_string, my_response_id, my_payload_hex_string);
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "DEBUG: directive is: %s\n", osdp_directive);
    status = send_osdp_command(ctx, "/opt/osdp-conformance/run/PD/open-osdp-control", osdp_directive);
  };
  return(status);

} /* main for pkoc-reader */
  

int pkoc_switches
  (PKOC_CONTEXT *ctx,
  int *command,
  int argc,
  char *argv [])

{ /* pkoc_switches */

  int done;
  int status;


  status = ST_OK;
  *command = PKOC_SWITCH_NOOP;
  done = 0;
  while (!done)
  {
    status_opt = getopt_long(argc, argv, optstring, longopts, &longindex);
    if (status_opt EQUALS -1)
    {
      done = 1;
      ctx->action = PKOC_SWITCH_NOOP;
    };
    switch(ctx->action)
    {
    case PKOC_SWITCH_CARD_PRESENT:
      fprintf(stderr, "PKOC: card present.\n");
      *command = ctx->action;
      status = ST_OK;
      break;
    case PKOC_SWITCH_NOOP:
      break;
    case PKOC_SWITCH_AUTH_REQUEST:
      fprintf(stderr, "PKOC: requesting authentication from card.\n");
      *command = ctx->action;
      status = ST_OK;
      break;
    case PKOC_SWITCH_HELP:
    default:
      fprintf(stderr, "--card-present - attempt to detect card and report\n");
      fprintf(stderr, "--help - display this help text.\n");
      fprintf(stderr, "--auth-request - request card authenticate\n");
      *command = ctx->action;
      status = ST_PKOC_UNKNOWN_SWITCH;
      break;
    };
  };
  return(status);

} /* pkoc_switches */

