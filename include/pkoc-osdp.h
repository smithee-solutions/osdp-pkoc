// pkoc-ospd.h

#define EQUALS ==
#define OSDP_MAX_PACKET_SIZE (1400)

#define ST_OK (0)
#define ST_PKOC_WRONG_OUI (1)
#define ST_PKOC_MALFORMED_PAYLOAD (2)
#define ST_PKOC_UNKNOWN_TAG       (3)
#define ST_PKOC_XTN_ID_TOO_LONG   (4)
#define ST_PKOC_BAD_SETTINGS      (5)

#define PKOC_STRING_MAX (1024)
#define PKOC_STATE_ACTIVATED (1)

#define OSDP_PKOC_CARD_PRESENT (0xE0)
#define OSDP_PKOC_AUTH_REQUEST (0xE1)
#define OSDP_PKOC_AUTH_RESPONSE (0xE2)
#define OSDP_PKOC_NEXT_TRANSACTION (0xE3)
#define OSDP_PKOC_TRANSACTION_IDENTIFER (0xE4)
#define OSDP_PKOC_READER_ERROR          (0xFE)
#define PKOC_TRANSACTION_ID_MAX (65)

typedef struct pkoc_context
{
  int verbosity;
  FILE *log;
  int current_state;
  unsigned char command_id;
  unsigned char response_id;
  unsigned int payload_mask;
  unsigned char transaction_id [PKOC_TRANSACTION_ID_MAX]; 
  unsigned char transaction_sequence; //check
  unsigned char oui [3];
  unsigned char payload [256];
  int payload_length;
  char oui_s [PKOC_STRING_MAX];
  char command_s [PKOC_STRING_MAX];
  char payload_s [PKOC_STRING_MAX];
} PKOC_CONTEXT;


#define PKOC_MAX_PAYLOAD_VALUES (8)
#define PAYLOAD_HAS_TRANSACTION_ID (0x0001)
#define IDX_XTN_ID (0)
typedef struct pkoc_payload_contents
{
  unsigned char tag;
  unsigned char length;
  unsigned char value [256];
} PKOC_PAYLOAD_CONTENTS;


int get_pkoc_settings(PKOC_CONTEXT *ctx);
int get_pkoc_state(PKOC_CONTEXT *ctx);
int match_oui(PKOC_CONTEXT *ctx);
int pkoc_parse(PKOC_CONTEXT *ctx, unsigned char * payload, int payload_length, PKOC_PAYLOAD_CONTENTS contents [], unsigned int *payload_mask);
int unpack_command(PKOC_CONTEXT *ctx, int argc, char *argv []);
int update_pkoc_state(PKOC_CONTEXT *ctx);

