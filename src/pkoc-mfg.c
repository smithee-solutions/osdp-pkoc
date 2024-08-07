/*
  pkoc-mfg - Manufacture-Specific Command processor for PKOC


  standard input is a one-line JSON.  1 is pd address, 2 is the OUI,
  3 is the command, 4 is the payload.

  - assumes state is in pkoc-state.json
  - assumes settings are in pkoc-settings.json
  - assumes multipart header

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

{ /* main for pkoc-mfg */

  PKOC_CONTEXT *ctx;
  int i;
  PKOC_CONTEXT my_context;
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
        ctx->command_id = i;
        switch(ctx->command_id)
        {
        default:
          fprintf(ctx->log, "Unknown mfg_command ID (%02X)\n", ctx->command_id);
          break;
        case OSDP_PKOC_NEXT_TRANSACTION:
          status = pkoc_parse(ctx, contents);
          if (status EQUALS ST_OK)
          {
            ctx->current_state = PKOC_STATE_ACTIVATED;
            if (ctx->payload_mask & PAYLOAD_HAS_TRANSACTION_ID)
              status = update_pkoc_state(ctx);

            system("/opt/osdp-conformance/bin/pkoc-reader --next-transaction");

            if (ctx->verbosity > 3)
              fprintf(ctx->log, "PKOC: MFG NEXT_TRANSACTION processed.\n");
          };
          break;
        case OSDP_PKOC_AUTH_REQUEST:
          system("/opt/osdp-conformance/bin/pkoc-reader --request-auth");
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "PKOC: MFG AUTH_REQUEST processed.\n");
          break;
        };
      };
    }
    else
    {
      fprintf(ctx->log, "MFG contains wrong OUI\n");
      status = ST_PKOC_WRONG_OUI;
    };
  };
  if (status != ST_OK)
    fprintf(ctx->log, "pkoc-mfg error %d.\n", status);
  return(status);

} /* main for pkoc-mfg.c */


int get_pkoc_state
  (PKOC_CONTEXT *ctx)
{
  //read pkoc-state.json
  return(0);
}

