/*
  pkoc-reader - perform smartcard actions for PKOC OSDP ACU Operations
*/

#include <stdio.h>
#include <string.h>

#include <pkoc-osdp.h>
#include <pkoc-osdp-version.h>

int main
  (int argc,
  char *argv [])

{ /* main for pkoc-reader */

  char my_oui_string [1024];
  OSDP_MULTIPART_HEADER my_payload_header;
  char my_payload_hex_string [1024];
  unsigned char my_response_id;
  char osdp_directive [8192];
  char tstring [3072];
  int status;


  status = ST_OK;

  fprintf(stderr, "pkoc-reader smartcard interface %s\n", PKOC_OSDP_VERSION);
  strcpy(my_oui_string, PKOC_OUI_STRING);
  my_response_id = OSDP_PKOC_CARD_PRESENT;

  my_payload_hex_string [0] = 0;
  strcpy(tstring, mph_in_hex(&my_payload_header));
  strcat(my_payload_hex_string, tstring);

  // response payload is
  // supported protocol version 5C 02 01 00
  // transaction sequence FD 01 00
  // error tlv FB 01 00

  strcpy(tstring, "5C020100FD0100FB0100");
  strcat(my_payload_hex_string, tstring);

/*
  initiate pcsc communications with card
  form mfgrep
  send mfgrep via osdp
*/

  if (status EQUALS ST_OK)
  {
    sprintf(osdp_directive,
"{\"command\":\"mfgrep\",\"oui\":\"%s\",\"response-id\":\"%02X\",\"response-specific-data\":\"%s\"}\n",
    my_oui_string, my_response_id, my_payload_hex_string);
fprintf(stderr, "DEBUG: directive is: %s\n", osdp_directive);
  };
  return(status);
}
  
