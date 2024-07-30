/*
  pkoc-mfg - Manufacture-Specific Command processor for PKOC


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
char *PKOC_OUI = "1A9021";


int main
  (int argc,
  char *argv [])

{ /* main for pkoc-mfg */

  int command_length;
  PKOC_CONTEXT *ctx;
  int i;
  unsigned char mfg_command [OSDP_MAX_PACKET_SIZE];
  PKOC_CONTEXT my_context;
  unsigned int payload_mask;
  int status;
  PKOC_PAYLOAD_CONTENTS contents [PKOC_MAX_PAYLOAD_VALUES];


  ctx = &my_context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->log = stderr;
  command_length = sizeof(mfg_command);
 
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
          status = pkoc_parse(ctx, mfg_command, command_length, contents, &payload_mask);
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

{ /* get_pkoc_settings */

  json_t *parameters;
  int status;
  json_error_t status_json;
  json_t *value;


  status = ST_OK;
  //read pkoc-settings.json

  parameters = json_load_file("pkoc-settings.json", 0, &status_json);
  if (parameters != NULL)
  {
    value = json_object_get(parameters, "verbosity");
    if (json_is_string(value))
    {
      sscanf(json_string_value(value), "%d", &(ctx->verbosity));
    };
  }
  else
  {
    status = ST_PKOC_BAD_SETTINGS;
  };
  return(status);

} /* get_pkoc_settings */


int match_oui
  (PKOC_CONTEXT *ctx)

{ /* match_oui */

  int match;


  match = 0;
  if (0 EQUALS strcmp(ctx->oui_s, PKOC_OUI))
    match = 1;
  return(match);

} /* match_oui */

