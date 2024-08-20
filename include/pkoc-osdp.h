/*
   pkoc-ospd.h - definitions for ACU authentication for PKOC

   Copyright 2024 Smithee Solutions LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/


#define EQUALS ==
#define OSDP_MAX_PACKET_SIZE (1400)


typedef struct __attribute__((packed)) osdp_multipart_header
{
  unsigned short int offset;
  unsigned short int fragment_length;
  unsigned short int total_length;
} OSDP_MULTIPART_HEADER;


#ifndef ST_OK
#define ST_OK (0)
#endif
#define ST_PKOC_WRONG_OUI (1)
#define ST_PKOC_MALFORMED_PAYLOAD (2)
#define ST_PKOC_UNKNOWN_TAG       (3)
#define ST_PKOC_XTN_ID_TOO_LONG   (4)
#define ST_PKOC_BAD_SETTINGS      (5)
#define ST_PKOC_NO_VERSION        (6)
#define ST_PKOC_OSDP_MISSING      (7)
#define ST_PKOC_PAYLOAD_TOO_SHORT (8)
#define ST_PKOC_UNKNOWN_SWITCH    (9)
#define ST_PKOC_PCSC_TRANSMIT     (10)

#define PKOC_STRING_MAX (1024)

#define PKOC_SWITCH_NOOP         (0)
#define PKOC_SWITCH_HELP         (1)
#define PKOC_SWITCH_AUTH_REQUEST (2)
#define PKOC_SWITCH_CARD_PRESENT (3)
#define PKOC_SWITCH_NEXT_TRANSACTION (4)

#define PKOC_STATE_ACTIVATED (1)
#define PKOC_STATE_READING   (2)
#define PKOC_STATE_AUTH_CHECK (3)


#define PKOC_OUI_STRING "1A9021"

#define OSDP_PKOC_CARD_PRESENT (0xE0)
#define OSDP_PKOC_AUTH_REQUEST (0xE1)
#define OSDP_PKOC_AUTH_RESPONSE (0xE2)
#define OSDP_PKOC_NEXT_TRANSACTION (0xE3)
#define OSDP_PKOC_TRANSACTION_IDENTIFER (0xE4)
#define OSDP_PKOC_READER_ERROR          (0xFE)

#define PKOC_TRANSACTION_ID_MAX (65)

#define PKOC_TAG_CARD_PRESENT           (0xFC)
#define PKOC_TAG_DIGITAL_SIGNATURE      (0x9E)
#define PKOC_TAG_ERROR                  (0xFB)
#define PKOC_TAG_PROTOCOL_VERSION       (0x5C)
#define PKOC_TAG_SYNC_SUPPORTED         (0xFA)
#define PKOC_TAG_TRANSACTION_IDENTIFIER (0x4C)
#define PKOC_TAG_READER_IDENTIFIER      (0x4D)
#define PKOC_TAG_UNCOMP_PUBLIC_KEY      (0x5A)
#define PKOC_TAG_XTN_SEQ                (0xFD)

typedef struct pkoc_context
{
  int action;
  unsigned char command_id;
  int current_state;
  FILE *log;
  unsigned int payload_mask;
  unsigned char protocol_version [2];
  unsigned char public_key [65];
  int public_key_length;
  int reader;
  unsigned char reader_identifier [32];
  unsigned char response_id;
  unsigned char signature [65];
  int signature_length;
  unsigned char transaction_identifier [PKOC_TRANSACTION_ID_MAX]; 
  int transaction_identifier_length;
  int verbosity;

  unsigned char transaction_sequence [2]; //check
  unsigned char oui [3];
  unsigned char payload [256];
  int payload_length;
  char oui_s [PKOC_STRING_MAX];
  char command_s [PKOC_STRING_MAX];
  char payload_s [PKOC_STRING_MAX];
} PKOC_CONTEXT;


#define PKOC_MAX_PAYLOAD_VALUES (8)
#define PAYLOAD_HAS_TRANSACTION_ID (0x0001)
#define PAYLOAD_HAS_PROTOVER       (0x8000)
#define PAYLOAD_HAS_XTN_SEQ        (0x4000)
#define PAYLOAD_HAS_ERROR          (0x2000)
#define PAYLOAD_HAS_PUBKEY         (0x1000)
#define PAYLOAD_HAS_SIGNATURE      (0x0800)
#define IDX_XTN_ID       (0)
#define IDX_PROTO_VER    (1)
#define IDX_XTN_SEQ      (2)
#define IDX_ERR          (3)
#define IDX_PUBKEY       (4)
#define IDX_SIG          (5)
typedef struct pkoc_payload_contents
{
  unsigned char tag;
  unsigned char length;
  unsigned char value [256];
} PKOC_PAYLOAD_CONTENTS;


int add_payload_element(PKOC_CONTEXT *ctx, char *command_buffer, int *command_buffer_length, unsigned char tag, unsigned char length, unsigned char *value);
int get_pkoc_settings(PKOC_CONTEXT *ctx);
int get_pkoc_state(PKOC_CONTEXT *ctx);
//int hex_to_binary(PKOC_CONTEXT *ctx, unsigned char *binary, int *length);
int init_smartcard(PKOC_CONTEXT *ctx);
int initialize_pubkey_DER(PKOC_CONTEXT *ctx, unsigned char *key_buffer, int kblth,
  unsigned char *marshalled_DER, int *marshalled_length);
int initialize_signature_DER(PKOC_CONTEXT *ctx, unsigned char *part_1, int part1lth,
  unsigned char *part_2, int part2lth, unsigned char *marshalled_signature, int *whole_sig_lth);
int match_oui(PKOC_CONTEXT *ctx);
char * mph_in_hex(OSDP_MULTIPART_HEADER *mph);
int pkoc_card_auth_request(PKOC_CONTEXT *ctx);
int pkoc_parse(PKOC_CONTEXT *ctx, PKOC_PAYLOAD_CONTENTS contents []);
int send_osdp_command(PKOC_CONTEXT *ctx, char *destination, char *command_string);
int unpack_command(PKOC_CONTEXT *ctx, int argc, char *argv []);
int update_pkoc_state(PKOC_CONTEXT *ctx, PKOC_PAYLOAD_CONTENTS contents []);
int validate_signature(PKOC_CONTEXT *ctx, unsigned char *public_key_bits);

