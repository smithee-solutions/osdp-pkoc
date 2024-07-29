/*
  pkoc-mfgrep - Manufacture-Specific Response processor for PKOC

  assumes state is in pkoc-state.json

  assumes settings are in pkoc-settings.json

  (C)2024 Smithee Solutions LLC
*/

// args per osdp interface for mfgrep command


#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include <pkoc-osdp.h>
unsigned char PKOC_OUI [3] = {0x1A, 0x90, 0x21};


int main
  (int argc,
  char *argv [])

{ /* main for pkoc-mfgrep */

  PKOC_CONTEXT *ctx;
  unsigned char mfg_response [OSDP_MAX_PACKET_SIZE];
  PKOC_CONTEXT my_context;
  unsigned int payload_mask;
  int response_length;
  int status;
  PKOC_PAYLOAD_CONTENTS contents [PKOC_MAX_PAYLOAD_VALUES];


  ctx = &my_context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->log = stderr;
  response_length = sizeof(mfg_response);
 
  status = get_pkoc_settings(ctx);
  if (status EQUALS ST_OK)
    status = unpack_response(ctx, argc, argv, mfg_response, &response_length);
  if (status EQUALS ST_OK)
  {
    if (match_oui(ctx, mfg_response))
    {
      status = get_pkoc_state(ctx);
      if (status EQUALS ST_OK)
      {
        switch(ctx->response_id)
        {
        default:
          fprintf(ctx->log, "Unknown mfg_command ID (%02X)\n", ctx->response_id);
          break;
        case OSDP_PKOC_NEXT_TRANSACTION:
          status = pkoc_parse(ctx, mfg_response, response_length, contents, &payload_mask);
          if (status EQUALS ST_OK)
          {
            ctx->current_state = PKOC_STATE_ACTIVATED;
            if (ctx->payload_mask & PAYLOAD_HAS_TRANSACTION_ID)
              status = update_pkoc_state(ctx);
          };
          break;
        case OSDP_PKOC_AUTH_REQUEST:
          system("card-reader --request-auth");
          break;
        };
      };
    }
    else
    {
      fprintf(ctx->log, "MFGREP contains wrong OUI (was %02X%02X%02X should be %02X%02X%02X)\n",
        ctx->oui [0], ctx->oui [1], ctx->oui [2],
        PKOC_OUI [0], PKOC_OUI [1], PKOC_OUI [2]);
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


int get_pkoc_settings
  (PKOC_CONTEXT *ctx)
{
  //read pkoc-settings.json
  return(0);
}


int match_oui
  (PKOC_CONTEXT *ctx,
  unsigned char * raw_response)
{
  int match;


  match = 0;
  if (raw_response [0] EQUALS PKOC_OUI [0])
    if (raw_response [1] EQUALS PKOC_OUI [1])
      if (raw_response [2] EQUALS PKOC_OUI [2])
        match = 1;
  return(match);
}

