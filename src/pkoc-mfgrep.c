/*
  pkoc-mfgrep - Manufacture-Specific Response processor for PKOC


  standard input is a one-line JSON.  1 is pd address, 2 is the OUI,
  3 is the command, 4 is the payload.

  - assumes state is in pkoc-state.json
  - assumes settings are in pkoc-settings.json

  (C)2024 Smithee Solutions LLC
*/


#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <jansson.h>


#include <pkoc-osdp.h>


int main
  (int argc,
  char *argv [])

{ /* main for pkoc-mfgrep */

  char command_buffer [8192];
  int command_buffer_length;
  PKOC_CONTEXT *ctx;
  int i;
  PKOC_CONTEXT my_context;
  char osdp_directive [8192];
  int status;
  PKOC_PAYLOAD_CONTENTS contents [PKOC_MAX_PAYLOAD_VALUES];


  ctx = &my_context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->log = stderr;
 
  status = get_pkoc_settings(ctx);
  if (status EQUALS ST_OK)
    status = unpack_command(ctx, argc, argv);
  if (status EQUALS ST_OK)
  {
    if (match_oui(ctx))
    {
      status = get_pkoc_state(ctx);
      if (status EQUALS ST_OK)
      {
        sscanf(ctx->command_s, "%x", &i);
        ctx->response_id = i;
        switch(ctx->response_id)
        {
        default:
          fprintf(ctx->log, "Unknown mfg response ID (%02X)\n", ctx->response_id);
          break;
        case OSDP_PKOC_CARD_PRESENT:
          status = pkoc_parse(ctx, contents);
          if (status EQUALS ST_OK)
          {
            ctx->current_state = PKOC_STATE_READING;
            if (ctx->payload_mask & PAYLOAD_HAS_PROTOVER)
              status = update_pkoc_state(ctx);
            else
              status = ST_PKOC_NO_VERSION;
          };

          /*
            there's a card.  do an auth request
          */
          command_buffer_length = 0;

          memset(command_buffer, 0, sizeof(command_buffer));
          command_buffer_length = 0;
          status = add_payload_element(ctx, command_buffer, &command_buffer_length,
            PKOC_TAG_PROTOCOL_VERSION, 2, contents [IDX_PROTO_VER].value);
          if (status EQUALS ST_OK)
            status = add_payload_element(ctx, command_buffer, &command_buffer_length,
              PKOC_TAG_TRANSACTION_IDENTIFIER, 65, ctx->transaction_identifier);
          if (status EQUALS ST_OK)
            status = add_payload_element(ctx, command_buffer, &command_buffer_length,
              PKOC_TAG_READER_IDENTIFIER, 32, ctx->reader_identifier);
          if (status EQUALS ST_OK)
            status = add_payload_element(ctx, command_buffer, &command_buffer_length,
              PKOC_TAG_XTN_SEQ, 2, ctx->transaction_sequence);
// how long is the transaction sequence?
           
          if (status EQUALS ST_OK)
          {
            char tstring1 [4096];
            char tstring2 [4096];
            OSDP_MULTIPART_HEADER my_payload_header;
            my_payload_header.offset = 0;
            my_payload_header.fragment_length = command_buffer_length/2;
            my_payload_header.total_length = my_payload_header.fragment_length;
            strcpy(tstring1, mph_in_hex(&my_payload_header));
            strcpy(tstring2, command_buffer);
            strcpy(command_buffer, tstring1);
            strcat(command_buffer, tstring2);
          };

          if (status EQUALS ST_OK)
          {
            sprintf(osdp_directive,
"{\"command\":\"mfg\",\"oui\":\"%s\",\"command-id\":\"%02X\",\"command-specific-data\":\"%s\"}\n",
    PKOC_OUI_STRING, OSDP_PKOC_AUTH_REQUEST, command_buffer);
fprintf(stderr, "DEBUG: directive is: %s\n", osdp_directive);
            status = send_osdp_command(ctx, "", osdp_directive);
          };
          break;
        };
      };
    }
    else
    {
      fprintf(ctx->log, "MFGREP contains wrong OUI\n");
      status = ST_PKOC_WRONG_OUI;
    };
  };
  if (status != ST_OK)
    fprintf(ctx->log, "pkoc-mfgrep error %d.\n", status);
  return(status);

} /* main for pkoc-mfgrep.c */


int get_pkoc_state
  (PKOC_CONTEXT *ctx)
{
  //read pkoc-state.json
  return(0);
}

