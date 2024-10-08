/*
  pkoc-nfc - NFC (samartcard) support routines for osdp-pkoc
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>

#include <eac-encode.h>
#include <openbadger-common.h>
#include <ob-pkoc.h>
#include <ob-7816.h>
#include <ob-pcsc.h>


#include <pkoc-osdp.h>
// 58 not 59?  todo - real wrapping
// also 41 not 42
unsigned char ec_public_key_der_skeleton [] =
{
  0x30,0x58,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x41,0x00
  // actual 65 byte key goes after this
};
unsigned char ec_signature_der_skeleton_1 [] =
{
  0x30,0x44,0x02,0x20,0x00 
// then 32 of part 1
};
unsigned char ec_signature_der_skeleton_2 [] =
{
  0x02,0x20,0x00 
// then 32 of part 2
};

OB_RDRCTX pcsc_reader_context;


int init_smartcard
  (PKOC_CONTEXT *ctx)

{
  DWORD dwRecvLength;
  OB_CONTEXT openbadger_context;
  BYTE pbRecvBuffer [2*OB_7816_APDU_PAYLOAD_MAX];
  unsigned char smartcard_command [OB_7816_BUFFER_MAX];
  int smartcard_command_length;
  int status;
  LONG status_pcsc;


  status = ST_OK;
  memset(&openbadger_context, 0, sizeof(openbadger_context));
  openbadger_context.log = ctx->log;
  openbadger_context.rdrctx= &pcsc_reader_context;
  openbadger_context.verbosity = ctx->verbosity;
  openbadger_context.reader_index = ctx->reader;
  if (status EQUALS ST_OK)
  {
    status = ob_init_smartcard(&openbadger_context);
  };
  if (status EQUALS ST_OK)
  {
    // construct select

    memcpy(smartcard_command, SELECT_PKOC, sizeof(SELECT_PKOC));
    smartcard_command_length = sizeof(SELECT_PKOC);
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "Select command ");
      ob_dump_buffer(&openbadger_context, smartcard_command, smartcard_command_length, OB_DUMP_LOG);
    };

    // send application select to card
    dwRecvLength = sizeof(pbRecvBuffer);
    status_pcsc = SCardTransmit(pcsc_reader_context.pcsc, &(pcsc_reader_context.pioSendPci), smartcard_command, smartcard_command_length, NULL, pbRecvBuffer, &dwRecvLength);

    pcsc_reader_context.last_pcsc_status = status_pcsc;
    if (SCARD_S_SUCCESS != status_pcsc)
      status = ST_PKOC_PCSC_TRANSMIT;
  };
  if (status EQUALS ST_OK)
  {
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "Select response ");
      ob_dump_buffer(&openbadger_context, pbRecvBuffer, dwRecvLength, OB_DUMP_LOG);
    };
    // last 2 should be 0x90 0x00
    // total should be 6
    // proto ver is value 

    status = -1;
    if (dwRecvLength EQUALS 6)
    {
      if ((pbRecvBuffer [dwRecvLength-2] EQUALS 0x90) &&
        (pbRecvBuffer [dwRecvLength-1] EQUALS 0x00))
      {
        memcpy(ctx->protocol_version, pbRecvBuffer+2, 2);
        status = ST_OK;
      };
    };
  };
  return(status);
}


int pkoc_card_auth_request
  (PKOC_CONTEXT *ctx)

{ /* pkoc_card_auth_request */

  EAC_ENCODE_CONTEXT crypto_context;
  DWORD dwRecvLength;
  int index_lc;
  unsigned char msg_cla;
  unsigned char msg_ins;
  unsigned char msg_lc;
  unsigned char msg_le;
  unsigned char msg_p1;
  unsigned char msg_p2;
  OB_CONTEXT ob_context;
  unsigned char *p;
  int payload_size;
  BYTE pbRecvBuffer [2*OB_7816_APDU_PAYLOAD_MAX];
  int remainder;
  unsigned char smartcard_command [OB_7816_BUFFER_MAX];
  int smartcard_command_length;
  int status;
  LONG status_pcsc;
unsigned char reader_key_identifier [OB_PKOC_READER_KEY_IDENTIFIER_LENGTH];
unsigned char site_key_identifier [OB_PKOC_SITE_KEY_IDENTIFIER_LENGTH];


  status = ST_OK;
fprintf(ctx->log,"DEBUG: site key identifier\n");
  memset(&ob_context, 0, sizeof(ob_context));
  ob_context.verbosity = ctx->verbosity;
  memset(&crypto_context, 0, sizeof(crypto_context));
  crypto_context.verbosity = ctx->verbosity;
  crypto_context.eac_log = eac_log;
  {
    // set up authentication command

    msg_cla = 0x80;
    msg_ins = 0x80;
    msg_p1 = 0x00;
    msg_p2 = 0x01;
    msg_lc = 0x00;
    msg_le = 0x00;
    smartcard_command_length = 0;
    memset(smartcard_command, 0, sizeof(smartcard_command));
    smartcard_command [smartcard_command_length] = msg_cla;
    smartcard_command_length++;
    smartcard_command [smartcard_command_length] = msg_ins;
    smartcard_command_length++;
    smartcard_command [smartcard_command_length] = msg_p1;
    smartcard_command_length++;
    smartcard_command [smartcard_command_length] = msg_p2;
    smartcard_command_length++;
    // fill in Lc later
    index_lc = smartcard_command_length;
    smartcard_command_length++;
    
    // tag,length,value - protocol version

    smartcard_command [smartcard_command_length] = OB_PKOC_TAG_PROTOCOL_VERSION;
    smartcard_command_length++;
    smartcard_command [smartcard_command_length] = 2;
    smartcard_command_length++;
    memcpy(smartcard_command+smartcard_command_length, ctx->protocol_version, 2);
    smartcard_command_length = smartcard_command_length + 2;
    
    /*
      tag,length,value - transaction id
      if no "message" specified fill in with padding.
    */
    smartcard_command [smartcard_command_length] = OB_PKOC_TAG_TRANSACTION_IDENTIFIER;
    smartcard_command_length++;
    smartcard_command [smartcard_command_length] = ctx->transaction_identifier_length;
    smartcard_command_length++;
    memcpy(smartcard_command+smartcard_command_length, ctx->transaction_identifier, ctx->transaction_identifier_length);

    fprintf(ctx->log, "Transaction Identifer:\n");
    ob_dump_buffer (&ob_context, smartcard_command+smartcard_command_length, ctx->transaction_identifier_length, OB_DUMP_LOG);
    smartcard_command_length = smartcard_command_length + ctx->transaction_identifier_length;
    
    // tag,length,value - reader identifier

    smartcard_command [smartcard_command_length] = OB_PKOC_TAG_READER_IDENTIFIER;
    smartcard_command_length++;
    smartcard_command [smartcard_command_length] = 0x20;
    smartcard_command_length++;
    memset(site_key_identifier, 'S', OB_PKOC_SITE_KEY_IDENTIFIER_LENGTH);
    memcpy(smartcard_command+smartcard_command_length, site_key_identifier, OB_PKOC_SITE_KEY_IDENTIFIER_LENGTH);
    smartcard_command_length = smartcard_command_length + 0x10;
    memset(reader_key_identifier, 'r', OB_PKOC_READER_KEY_IDENTIFIER_LENGTH);
    memcpy(smartcard_command+smartcard_command_length, reader_key_identifier, OB_PKOC_READER_KEY_IDENTIFIER_LENGTH);
    smartcard_command_length = smartcard_command_length + 0x10;
    msg_lc = smartcard_command_length - index_lc - 1;
    smartcard_command [index_lc] = msg_lc;
    smartcard_command [smartcard_command_length] = msg_le;
    smartcard_command_length++;

    fprintf(ctx->log, "Marshalled Authentication Command:\n");
    ob_dump_buffer (&ob_context, smartcard_command, smartcard_command_length, OB_DUMP_LOG);
  };
  if (status EQUALS ST_OK)
  {
    // send authentication command to card

    dwRecvLength = sizeof(pbRecvBuffer);
    status_pcsc = SCardTransmit(pcsc_reader_context.pcsc, &(pcsc_reader_context.pioSendPci), smartcard_command, smartcard_command_length, NULL, pbRecvBuffer, &dwRecvLength);
    pcsc_reader_context.last_pcsc_status = status_pcsc;
    if (SCARD_S_SUCCESS != status_pcsc)
      status = STOB_PKOC_AUTH;
  };
  if (status EQUALS ST_OK)
  {
    fprintf(ctx->log, "Authentication returns:\n");
    ob_dump_buffer (&ob_context, pbRecvBuffer, dwRecvLength, OB_DUMP_LOG);
  };
  if (status EQUALS ST_OK)
  {
    // extract the signature and public key.  in tlv, arbitrary order.

    p = pbRecvBuffer;
    remainder = dwRecvLength;
    if (*p EQUALS OB_PKOC_TAG_UNCOMP_PUBLIC_KEY)
    {
      p++;
      remainder = remainder -1;
      payload_size = *p;
      p++;
      remainder = remainder - 1;

      memcpy(ctx->public_key, p, payload_size);
      ctx->public_key_length = payload_size;

      p = p + payload_size;
      remainder = remainder - payload_size;
    };
    if (*p EQUALS OB_PKOC_TAG_DIGITAL_SIGNATURE)
    {
      p++;
      remainder--;
      payload_size = *p;
      p++;
      remainder--;

      memcpy(ctx->signature, p, payload_size);
      ctx->signature_length = payload_size;

      p = p + payload_size;
      remainder = remainder - payload_size;
    };
    if (*p EQUALS OB_PKOC_TAG_UNCOMP_PUBLIC_KEY)
    {
      p++;
      remainder--;
      payload_size = *p;
      p++;
      remainder--;

      memcpy(ctx->public_key, p, payload_size);
      ctx->public_key_length = payload_size;

      p = p + payload_size;
      remainder = remainder - payload_size;
    };
    fprintf(ctx->log, "Public Key:\n");
    ob_dump_buffer (&ob_context, ctx->public_key, ctx->public_key_length, OB_DUMP_LOG);
    fprintf(ctx->log, "Signature:\n");
    ob_dump_buffer (&ob_context, ctx->signature, ctx->signature_length, OB_DUMP_LOG);
  };
  return(status);

} /* pkoc_card_auth_request */


int initialize_pubkey_DER
  (PKOC_CONTEXT *ctx,
  unsigned char *key_buffer,
  int kblth,
  unsigned char *marshalled_DER,
  int *marshalled_length)

{ /* intiialize_pubkey_DER */

  FILE *ec_der_key;


  ec_der_key = fopen(OBTEST_PKOC_PUBLIC_KEY, "w");
  fwrite(ec_public_key_der_skeleton, 1, sizeof(ec_public_key_der_skeleton), ec_der_key);
  memcpy(marshalled_DER, ec_public_key_der_skeleton, sizeof(ec_public_key_der_skeleton));
  fwrite(key_buffer, 1, kblth, ec_der_key);
  memcpy(marshalled_DER+sizeof(ec_public_key_der_skeleton), key_buffer, kblth);
  fclose(ec_der_key);
  *marshalled_length = sizeof(ec_public_key_der_skeleton) + kblth;

  return(ST_OK);

} /* intiialize_pubkey_DER */


int initialize_signature_DER
  (PKOC_CONTEXT *ctx,
  unsigned char *part_1,
  int part1lth,
  unsigned char *part_2,
  int part2lth,
  unsigned char *marshalled_signature,
  int *whole_sig_lth)

{ /* initialize_signature_DER */

  FILE *ec_der_sig;
  int lth;
  unsigned char *pwholesig;
  int whole_length;


  // if the pieces have the high order bit set insert a null byte

  // fiddle the outer length accordingly

  whole_length = 32 + 32 + 4;
  if (0x80 & *part_1)
  {
    whole_length++;
    ec_signature_der_skeleton_1 [3] = 0x21;
    if (ctx->verbosity > 9)
      fprintf(ctx->log, "part 1 first octet %02X\n", *part_1);
  };
  if (0x80 & *part_2)
  {
    whole_length++;
    ec_signature_der_skeleton_2 [1] = 0x21;
    if (ctx->verbosity > 9)
      fprintf(ctx->log, "part 2 first octet %02X\n", *part_2);
  };
  ec_signature_der_skeleton_1 [1] = whole_length;

  ec_der_sig = fopen("ec-sig.der", "w");
  lth = sizeof(ec_signature_der_skeleton_1);
  if (!(0x80 & *part_1))
    lth--;
  if (ctx->verbosity > 9)
    fprintf(ctx->log, "part 1 write length %d.\n", lth);

  fwrite(ec_signature_der_skeleton_1, 1, lth, ec_der_sig);
  pwholesig = marshalled_signature;
  memcpy(pwholesig, ec_signature_der_skeleton_1, lth);
  pwholesig = pwholesig + lth;
  *whole_sig_lth = lth;

  fwrite(part_1, 1, part1lth, ec_der_sig);
  memcpy(pwholesig, part_1, part1lth);
  pwholesig = pwholesig + part1lth;
  *whole_sig_lth = *whole_sig_lth + part1lth;

  lth = sizeof(ec_signature_der_skeleton_2);
  if (!(0x80 & *part_2))
    lth--;
  if (ctx->verbosity > 9)
    fprintf(ctx->log, "part 2 write length %d.\n", lth);

  fwrite(ec_signature_der_skeleton_2, 1, lth, ec_der_sig);
  memcpy(pwholesig, ec_signature_der_skeleton_2, lth);
  pwholesig = pwholesig + lth;
  *whole_sig_lth = *whole_sig_lth + lth;

  fwrite(part_2, 1, part2lth, ec_der_sig);
  memcpy(pwholesig, part_2, part2lth);
  *whole_sig_lth = *whole_sig_lth + part2lth;

  fclose(ec_der_sig);
  return(ST_OK);

} /* initialize_signature_DER */

