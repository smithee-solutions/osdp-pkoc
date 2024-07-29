#include <stdio.h>
#include <string.h>


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


int unpack_response
  (PKOC_CONTEXT *ctx,
  int argc,
  char *argv [],
  unsigned char *mfg_response,
  int *response_length)

{
  *response_length = 0;
  *mfg_response = 0;
  return(ST_OK);
}

int update_pkoc_state
  (PKOC_CONTEXT *ctx)
{
  return(ST_OK);
}


