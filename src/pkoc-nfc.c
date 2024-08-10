// pkoc nfc (i.e. smartcard pcsc) support


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-pkoc.h>
#include <ob-7816.h>
#include <ob-pcsc.h>


#include <pkoc-osdp.h>

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
      fprintf(stderr, "Select command ");
      ob_dump_buffer(&openbadger_context, smartcard_command, smartcard_command_length, 0);
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
      fprintf(stderr, "Select response ");
      ob_dump_buffer(&openbadger_context, pbRecvBuffer, dwRecvLength, 0);
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

{
  return (ST_OK);
}

