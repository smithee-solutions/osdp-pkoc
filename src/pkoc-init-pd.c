/*
  pkoc-init-pd - initialize PD for PKOC

  (C)2024 Smithee Solutions LLC
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkoc-osdp.h>


int main
  (int argc,
  char *argv [])

{ /* main for pkoc-init-pd */

  char settings_string [PKOC_STRING_MAX];
  FILE *sf;

  fprintf(stderr, "Clearing out PKOC state.\n");
  system("rm -f pkoc-state.json");
  if (1 /* pkoc-settings does not exist */)
  {
    strcpy(settings_string, "{\"verbosity\":\"9\"}");
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

