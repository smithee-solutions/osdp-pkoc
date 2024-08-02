#include <stdio.h>
#include <string.h>

#include <jansson.h>


#include <pkoc-osdp.h>


/*
  adds tlv (value is binary) to command buffer.  buffer is hex.
*/
int add_payload_element
  (PKOC_CONTEXT *ctx,
  char *command_buffer,
  int *command_buffer_length,
  unsigned char tag,
  unsigned char length,
  unsigned char *value)

{ /* add_payload_element */

  int i;
  char payload_temp [1024];
  char tstring [1024];


  payload_temp [0] = 0;
  sprintf(tstring, "%02X%02X", tag, length);
  strcat(payload_temp, tstring);
  for (i=0; i<length; i++)
  {
    sprintf(tstring, "%02X", value [i]);
    strcat(payload_temp, tstring);
  };
  strcpy(command_buffer, payload_temp);
  *command_buffer_length = strlen(payload_temp);
  return(ST_OK);
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
  if (0 EQUALS strcmp(ctx->oui_s, PKOC_OUI_STRING))
    match = 1;
  return(match);

} /* match_oui */


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


  parsed = 0;
  status = hex_to_binary(ctx, payload, &payload_length);
  p = payload;
  if (payload_length < 6) // 2+2+2 header in actual payload
    status = ST_PKOC_PAYLOAD_TOO_SHORT;
  if (status EQUALS ST_OK)
  {
    status = ST_PKOC_MALFORMED_PAYLOAD;
    parsed = 0;
    ctx->payload_mask = 0;

    // skip over the (generic) multipart header
    if (ctx->verbosity > 3)
    {
      unsigned short int l1;
      unsigned short int l2;
      unsigned short int l3;
      memcpy(&l1, p, 2);
      p = p + 2;
      payload_length = payload_length -2;
      memcpy(&l2, p, 2);
      p = p + 2;
      payload_length = payload_length -2;
      memcpy(&l3, p, 2);
      p = p + 2;
      payload_length = payload_length -2;
    };

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
        case PKOC_TAG_TRANSACTION_IDENTIFIER:
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
        case PKOC_TAG_PROTOCOL_VERSION:
          ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_PROTOVER;
          if (length EQUALS 2)
            memcpy(ctx->protocol_version, p, length);
          p = p + length;
          unprocessed = unprocessed - length;
          status = ST_OK;
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

