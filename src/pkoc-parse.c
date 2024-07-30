#include <stdio.h>
#include <string.h>

#include <jansson.h>


#include <pkoc-osdp.h>


/*
  parsing for PKOC is simple:
    length always one octet
    only one of any given field

  note they may be in any order

  mask returned say which is present.
*/

int pkoc_parse
  (PKOC_CONTEXT *ctx,
  unsigned char * payload,
  int payload_length,
  PKOC_PAYLOAD_CONTENTS contents [],
  unsigned int *payload_mask)

{ /* pkoc_parse */

  int done;
  int length;
  unsigned char *p;
  int parsed;
  int status;
  unsigned char tag;
  int unprocessed;


  status = ST_PKOC_MALFORMED_PAYLOAD;
  parsed = 0;
  *payload_mask = 0;

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
      case OSDP_PKOC_NEXT_TRANSACTION:
        if (length EQUALS 0)
        {
          *payload_mask = *payload_mask | PAYLOAD_HAS_TRANSACTION_ID;
        }
        else
        {
          if (length > PKOC_TRANSACTION_ID_MAX)
            status = ST_PKOC_XTN_ID_TOO_LONG;
          else
          {
            *payload_mask = *payload_mask | PAYLOAD_HAS_TRANSACTION_ID;
            contents [IDX_XTN_ID].tag = OSDP_PKOC_NEXT_TRANSACTION;
            contents [IDX_XTN_ID].length = length;
            memcpy(contents [IDX_XTN_ID].value, p, length);
            p = p + length;
            unprocessed = unprocessed - length;
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
  
  return(status);

} /* pkoc_parse */


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
  return(ST_OK);
}


