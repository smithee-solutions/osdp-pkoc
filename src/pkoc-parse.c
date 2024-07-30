#include <stdio.h>
#include <string.h>

#include <jansson.h>


#include <pkoc-osdp.h>


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


/*
  parsing for PKOC is simple:
    length always one octet
    only one of any given field

  note they may be in any order

  mask returned say which is present.
*/

int pkoc_parse
  (PKOC_CONTEXT *ctx,
  PKOC_PAYLOAD_CONTENTS contents [])

{ /* pkoc_parse */

  int done;
  int length;
  unsigned char *p;
  int parsed;
  unsigned char payload [OSDP_MAX_PACKET_SIZE];
  int payload_length;
  int status;
  unsigned char tag;
  int unprocessed;


  status = hex_to_binary(ctx, payload, &payload_length);
  if (status EQUALS ST_OK)
  {

  status = ST_PKOC_MALFORMED_PAYLOAD;
  parsed = 0;
  ctx->payload_mask = 0;

  if ((payload_length EQUALS 1) && (*payload EQUALS 0))
  {
    status = ST_OK;
    parsed = 1;
  };
  if (!parsed)
  {
    if (payload_length EQUALS 0)
    {
    status = ST_OK;
    parsed = 1;
    };
  };
  if (!parsed)
  {
    done = 0;
    p = payload;
    unprocessed = payload_length;
    while (!done)
    {
      tag = *p; p++; unprocessed --;
      length = *p; p++; unprocessed --;
      switch (tag)
      {
      default:
        status = ST_PKOC_UNKNOWN_TAG;
        parsed = 1;
        done = 1;
        break;
      case PKOC_TAG_TRANSACTION_IDENTIFER:
        if (length EQUALS 0)
        {
          ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_TRANSACTION_ID;
          status = ST_OK;
        }
        else
        {
          if (length > PKOC_TRANSACTION_ID_MAX)
            status = ST_PKOC_XTN_ID_TOO_LONG;
          else
          {
            ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_TRANSACTION_ID;
            contents [IDX_XTN_ID].tag = OSDP_PKOC_NEXT_TRANSACTION;
            contents [IDX_XTN_ID].length = length;
            memcpy(contents [IDX_XTN_ID].value, p, length);
            p = p + length;
            unprocessed = unprocessed - length;
            status = ST_OK;
          };
        };
        break;
      };
      if (unprocessed < 2)
        done = 1; 
      if (status != ST_OK)
        done = 1;
    };
  };
  };
  
  return(status);

} /* pkoc_parse */


int hex_to_binary
  (PKOC_CONTEXT *ctx,
  unsigned char *binary,
  int *length)

{ /* hex_to_binary */

  int count;
  int hexit;
  char octet_string [3];
  char *p;
  unsigned char *pbinary;


  *length = 0;
  p = ctx->payload_s;
  pbinary = binary;
  count = strlen(ctx->payload_s);
  if ((count % 2) != 0)
  {
    count = count - 1;
    fprintf(ctx->log, "trimming hex string to even number of hexits.\n");
  };
  while (count > 0)
  {
    memcpy(octet_string, p, 2);
    octet_string [2] = 0;
    sscanf(octet_string, "%x", &hexit);
    *pbinary = hexit;
    pbinary++;
    p = p + 2;
    count = count - 2;
    (*length)++;
  };

  return(ST_OK);

} /* hex_to_binary */


/*
  unpack_command - converts the json input into parsed values

  accepts argc/argv so it can use non-stdin input in the future.
*/

int unpack_command
  (PKOC_CONTEXT *ctx,
  int argc,
  char *argv [])

{ /* unpack_command */

  char json_command [8192];
  json_t *mfg_command;
  char *status_io;
  json_error_t status_json;
  json_t *value;


  status_io = fgets(json_command, sizeof(json_command), stdin);
  if (status_io != NULL)
  {
    mfg_command = json_loads(json_command, 0, &status_json);
    if (mfg_command != NULL)
    {
      value = json_object_get(mfg_command, "2");
      if (json_is_string(value))
        strcpy(ctx->oui_s, json_string_value(value));
      value = json_object_get(mfg_command, "3");
      if (json_is_string(value))
        strcpy(ctx->command_s, json_string_value(value));
      value = json_object_get(mfg_command, "4");
      if (json_is_string(value))
        strcpy(ctx->payload_s, json_string_value(value));
    };
  };
  return(ST_OK);

} /* unpack_command */


int update_pkoc_state
  (PKOC_CONTEXT *ctx)
{
  FILE *state;

  state = fopen("pkoc-state.json", "w");
  fprintf(state, "{\"state\":\"%d\"}\n", ctx->current_state);
  fclose(state);

  return(ST_OK);
}
