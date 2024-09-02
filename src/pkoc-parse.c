#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <jansson.h>

#include <eac-encode.h>
#include <openbadger-common.h>


#include <pkoc-osdp.h>
int pkoc_hex_to_binary(PKOC_CONTEXT *ctx, unsigned char *binary, int *length);


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
  if (parameters EQUALS NULL)
  {
    if (parameters EQUALS NULL)
      fprintf(ctx->log, "local settings not found, using %s\n",
        "/opt/osdp/etc/pkoc-settings.json");
    parameters = json_load_file("/opt/osdp/etc/pkoc-settings.json", 0, &status_json);
    if (parameters EQUALS NULL)
      fprintf(ctx->log, "global settings not found (%s)\n",
        "/opt/osdp/etc/pkoc-settings.json");
  };
  if (parameters != NULL)
  {
    value = json_object_get(parameters, "verbosity");
    if (json_is_string(value))
    {
      sscanf(json_string_value(value), "%d", &(ctx->verbosity));
    };
    value = json_object_get(parameters, "reader");
    if (json_is_string(value))
    {
      sscanf(json_string_value(value), "%d", &(ctx->reader));
    };
  };
  return(status);

} /* get_pkoc_settings */


int get_pkoc_state
  (PKOC_CONTEXT *ctx)
{
  //read pkoc-state.json
fprintf(ctx->log, "DEBUG: stub get_pkoc_state\n");
ctx->transaction_identifier_length = 16;
memset(ctx->transaction_identifier, 0x17, 16);
  return(0);
}


int match_oui
  (PKOC_CONTEXT *ctx)

{ /* match_oui */

  int match;


  match = 0;
  if (0 EQUALS strcmp(ctx->oui_s, PKOC_OUI_STRING))
    match = 1;
  return(match);

} /* match_oui */


char * mph_in_hex
  (OSDP_MULTIPART_HEADER *mph)

{ /* mph_in_hex */

  static char answer [2048];
  sprintf(answer, "%04X%04X%04X", htons(mph->offset), htons(mph->fragment_length), htons(mph->total_length));
  return(answer);

} /* mph_in_hex */


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
  OSDP_MULTIPART_HEADER *mph;
  OB_CONTEXT ob_context;
  unsigned char *p;
  int parsed;
  unsigned char payload [OSDP_MAX_PACKET_SIZE];
  int payload_length;
  int status;
  unsigned char tag;
  int unprocessed;


  parsed = 0;
  ob_context.verbosity = ctx->verbosity;
  status = pkoc_hex_to_binary(ctx, payload, &payload_length);
  p = payload;
  if (payload_length < 6) // 2+2+2 header in actual payload
    status = ST_PKOC_PAYLOAD_TOO_SHORT;
  if (status EQUALS ST_OK)
  {
    status = ST_PKOC_MALFORMED_PAYLOAD;
    parsed = 0;
    ctx->payload_mask = 0;
    mph = (OSDP_MULTIPART_HEADER *)p;
    p = p + sizeof(*mph);
    payload_length = payload_length - sizeof(*mph);

    // skip over the (generic) multipart header
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "DEBUG: multipart offset %04x fraglth %04x totlth %04x\n",
        ntohs(mph->offset), ntohs(mph->fragment_length), ntohs(mph->total_length));
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
fprintf(ctx->log, "index %d. ", (int)(p-payload));
        tag = *p; p++; unprocessed --;
        length = *p; p++; unprocessed --;
fprintf(ctx->log, " tag %02X length %02X\n", tag, length);
        switch (tag)
        {
        default:
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "Unknown tag %02X\n", tag);
          status = ST_PKOC_UNKNOWN_TAG;
          parsed = 1;
          done = 1;
          break;
        case PKOC_TAG_ERROR:
          ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_ERROR;
          contents [IDX_ERR].tag = tag;
          contents [IDX_ERR].length = length;
          memcpy(contents [IDX_ERR].value, p, length);
          p = p + length;
          unprocessed = unprocessed - length;
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "Tag: Error Status %02X...\n",
              contents [IDX_ERR].value [0]);
          status = ST_OK;
          break;
        case PKOC_TAG_PROTOCOL_VERSION:
          ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_PROTOVER;
          if (length EQUALS 2)
          {
            contents [IDX_PROTO_VER].tag = tag;
            contents [IDX_PROTO_VER].length = length;
            memcpy(contents [IDX_PROTO_VER].value, p, length);
          };
          p = p + length;
          unprocessed = unprocessed - length;
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "Tag: Protocol Version %02X%02X\n",
              contents [IDX_PROTO_VER].value [0], contents [IDX_PROTO_VER].value [1]);
          status = ST_OK;
          break;
        case PKOC_TAG_DIGITAL_SIGNATURE:
          ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_SIGNATURE;
          {
            contents [IDX_SIG].tag = tag;
            contents [IDX_SIG].length = length;
            memcpy(contents [IDX_SIG].value, p, length);
          };
          p = p + length;
          unprocessed = unprocessed - length;
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "Tag: Signature %02X...\n",
              contents [IDX_SIG].value [0]);
          status = ST_OK;
          break;
        case PKOC_TAG_UNCOMP_PUBLIC_KEY:
          ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_PUBKEY;
          {
            contents [IDX_PUBKEY].tag = tag;
            contents [IDX_PUBKEY].length = length;
            memcpy(contents [IDX_PUBKEY].value, p, length);
          };
          p = p + length;
          unprocessed = unprocessed - length;
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "Tag: Public Key %02X...\n",
              contents [IDX_PUBKEY].value [0]);
          status = ST_OK;
          break;
        case PKOC_TAG_TRANSACTION_IDENTIFIER:
          if (length EQUALS 0)
          {
            ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_TRANSACTION_ID;
            contents [IDX_XTN_ID].tag = tag;
            contents [IDX_XTN_ID].length = 0;
            unprocessed = unprocessed - length;
            status = ST_OK;
          }
          else
          {
            if (length > PKOC_TRANSACTION_ID_MAX)
              status = ST_PKOC_XTN_ID_TOO_LONG;
            else
            {
              ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_TRANSACTION_ID;
              contents [IDX_XTN_ID].tag = tag;
              contents [IDX_XTN_ID].length = length;
              memcpy(contents [IDX_XTN_ID].value, p, length);
              p = p + length;
              unprocessed = unprocessed - length;
              status = ST_OK;
            };
          };
          if (status EQUALS ST_OK)
            if (ctx->verbosity > 3)
              fprintf(ctx->log, "Tag: Transaction ID (l=%d.) %02X...\n",
                contents [IDX_XTN_ID].length, contents [IDX_XTN_ID].value [0]);
          break;
        case PKOC_TAG_XTN_SEQ:
          ctx->payload_mask = ctx->payload_mask | PAYLOAD_HAS_XTN_SEQ;
          contents [IDX_XTN_SEQ].tag = tag;
          contents [IDX_XTN_SEQ].length = length;
          memcpy(contents [IDX_XTN_SEQ].value, p, length);
          p = p + length;
          unprocessed = unprocessed - length;
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "Tag: Transaction Sequence (l=%d) %02X...\n",
              contents [IDX_XTN_SEQ].length, contents [IDX_XTN_SEQ].value [0]);
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


int pkoc_hex_to_binary
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
  (PKOC_CONTEXT *ctx,
  PKOC_PAYLOAD_CONTENTS contents [])

{ /* update_pkoc_state */

  FILE *state;

  state = fopen("pkoc-state.json", "w");
  fprintf(state, "{\"_\":\"0\"");
  fprintf(state, ", \"state\":\"%d\"", ctx->current_state);
  fprintf(state, ", \"transaction-id\":\"%X%X\"}\n",
    contents [IDX_XTN_ID].value [0],
    contents [IDX_XTN_ID].value [1]);
  fprintf(state, "}\n");
  fclose(state);

  return(ST_OK);

} /* update_pkoc_state */


int validate_signature
  (PKOC_CONTEXT *ctx, 
  unsigned char *public_key_bits)

{ /* validate_signature */

  EAC_ENCODE_CONTEXT crypto_context;
  unsigned char digest [EAC_CRYPTO_SHA256_DIGEST_SIZE];
  int digest_lth;
  EAC_ENCODE_OBJECT digest_object;
  OB_CONTEXT ob_context;
  unsigned char pkoc_signature [EAC_CRYPTO_MAX_DER];
  unsigned char pubkey_der [8192];
  int pubkey_der_length;
  EAC_ENCODE_OBJECT public_key;
  EAC_ENCODE_OBJECT signature_info;
  EAC_ENCODE_OBJECT signature_object;
  int status;
  unsigned char whole_sig [16384];
  int whole_sig_lth;


  if (ctx->verbosity > 3)
    fprintf(ctx->log, "validate_signature: top\n");
  status = ST_OK;
  memset(&ob_context, 0, sizeof(ob_context));
  ob_context.verbosity = ctx->verbosity;
  memset(&crypto_context, 0, sizeof(crypto_context));
  crypto_context.verbosity = ctx->verbosity;
  crypto_context.eac_log = eac_log;
  memset(public_key_bits, 0, 65);
  whole_sig_lth = 0;

// clean up 65

  if (status EQUALS ST_OK)
  {
    status = eac_encode_allocate_object(&crypto_context, &public_key);
    if (status != ST_OK)
      fprintf(ctx->log, "Error: object alloc (public_key) (%d.)\n",
        status);
  };
  if (status EQUALS ST_OK)
  {
int public_key_length;
int signature_length;
public_key_length = 64;
signature_length = 64;
fprintf(ctx->log, "DEBUG: check validate lth sig lth pubkey (%d ?)\n", public_key_length);
    fprintf(ctx->log, "Public Key:\n");
    ob_dump_buffer (&ob_context, ctx->public_key, public_key_length, 0);
    fprintf(ctx->log, "Signature:\n");
    ob_dump_buffer (&ob_context, ctx->signature, signature_length, 0);

    // output a DER-formatted copy of the public key.
    pubkey_der_length = sizeof(pubkey_der);
    status = initialize_pubkey_DER(ctx, ctx->public_key, public_key_length, pubkey_der, &pubkey_der_length);
fprintf(ctx->log, "DEBUG: shoulda been proper length\n");
  };
  if (status EQUALS ST_OK)
  {
    fprintf(ctx->log, "DER Encoded Public Key:\n");
    ob_dump_buffer(&ob_context, pubkey_der, pubkey_der_length, 0);
  };
  if (status EQUALS ST_OK)
  {
    status = eac_crypto_digest_init(&crypto_context, &digest_object);
  };
  if (status EQUALS ST_OK)
  {
    // transaction identifier was kept in the pkoc state.

    status = eac_crypto_digest_update(&crypto_context, &digest_object, ctx->transaction_identifier, ctx->transaction_identifier_length);
  };
  if (status EQUALS ST_OK)
     status = eac_crypto_digest_finish(&crypto_context, &digest_object, digest, &digest_lth);
  if (status EQUALS ST_OK)
  {
    if (crypto_context.verbosity > 3)
    {
      fprintf(ctx->log, "digest...\n");
      ob_dump_buffer(&ob_context, digest, digest_lth, 0);
    };
  };

  if (status EQUALS ST_OK)
  {
    public_key.key_parameters [0] = EAC_CRYPTO_EC;
    public_key.key_parameters [1] = EAC_KEY_EC_CURVE_SECP256R1;
    strcpy(public_key.description, DESC_EC256);

    status = eac_crypto_pubkey_init(&crypto_context, &public_key, pubkey_der, pubkey_der_length);
  };
  if (status EQUALS ST_OK)
  {
    if (ctx->verbosity > 3)
    {
      if (strlen(public_key.description) > 0)
      {
        fprintf(ctx->log, "public key init status %d public key type is %s\n", status, public_key.description);
      };
    };
  };
  if (status EQUALS ST_OK)
    status = initialize_signature_DER(ctx, pkoc_signature, 32, pkoc_signature+32, 32, whole_sig, &whole_sig_lth);
  if (status EQUALS ST_OK)
  {
    memcpy(signature_object.encoded, whole_sig, whole_sig_lth);
    signature_object.enc_lth = whole_sig_lth;
    status = eac_crypto_verify_signature_ex(&crypto_context,
      &public_key, digest, digest_lth,
      &signature_object, &signature_info);
    if (status EQUALS ST_OK)
      fprintf(ctx->log, "***SIGNATURE VALID***\n");
  };
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "validate_signature: exit, status %d\n", status);
  return(status);

} /* validate_signature */

