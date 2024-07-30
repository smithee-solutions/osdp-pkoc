/*
  pkoc-init-pd - initialize PD for PKOC

  (C)2024 Smithee Solutions LLC
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include <pkoc-osdp.h>


int main
  (int argc,
  char *argv [])

{ /* main for pkoc-init-pd */

  json_t *parameters;
  char settings_string [PKOC_STRING_MAX];
  FILE *sf;
  json_error_t status_json;

  fprintf(stderr, "Clearing out PKOC state.\n");
  system("rm -f pkoc-state.json");

  strcpy(settings_string, 
"{\"verbosity\":\"9\"}\n");

  parameters = json_load_file("pkoc-settings.json", 0, &status_json);
  if (parameters EQUALS NULL)
  {
    sf = fopen("pkoc-settings.json", "w");
    fprintf(sf, "%s\n", settings_string);
fprintf(stderr, "DEBUG: do init cleanly\n");
  }
  else
  {
    fprintf(stderr,"read exising settings and display\n");
  };
  return(ST_OK);
}

