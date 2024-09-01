/*
  pkoc-mfg - Manufacture-Specific Command processor for PKOC

  standard input is a one-line JSON.  1 is pd address, 2 is the OUI,
  3 is the command, 4 is the payload.

  - assumes state is in pkoc-state.json
  - assumes settings are in /opt/osdp-conformance/etc/pkoc-settings.json
  - assumes multipart header

  Writes log to /opt/osdp/log/osdp-pkoc-pd.log

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
  ctx->log = fopen("/opt/osdp/log/osdp-pkoc-pd.log", "a");
  if (ctx->log EQUALS NULL)
  {
    ctx->log = stderr;
    fprintf(stderr, "Log open failed (%s), falling back to stderr\n", "/opt/osdp/log/osdp-pkoc-pd.log");
  };
 
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
            {
              if (contents [IDX_XTN_ID].length > 2)
                fprintf(ctx->log, "PKOC MFG: Warning - transaction ID is %d. bytes\n", contents [IDX_XTN_ID].length);
              if (ctx->verbosity > 3)
              {
                fprintf(ctx->log, "Panel provided transaction id (l=%d) %02X%02X...\n",
                  contents [IDX_XTN_ID].length, contents [IDX_XTN_ID].value [0], contents [IDX_XTN_ID].value [1]);
              };
              status = update_pkoc_state(ctx, contents);
              if (ctx->verbosity > 3)
                fprintf(ctx->log, "PKOC: MFG NEXT_TRANSACTION processed.\n");
            };
          };
          break;
        case OSDP_PKOC_AUTH_REQUEST:
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "PKOC: Processing MFG AUTH_REQUEST.\n");
          system("/opt/osdp-conformance/bin/pkoc-reader --auth-request");
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

