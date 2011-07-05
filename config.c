/*
  radreplay - radius test program which replays tcpdumps
  Copyright (C) 2011 Ben Brown, Plusnet plc
  
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "radreplay.h"

char *find_config_file(void)
{
  char *config_file = NULL;
  char *homedir = getenv("HOME");
  struct stat st;

  memset(&st, 0, sizeof(st));

  debugPrint("entered find_config_file\n");

  if (homedir)
  {
    debugPrint("Looking for %s/.radreplayrc\n", homedir);
    /* size calculation:
     * strlen(homedir) + strlen("/.radreplayrc") + \0
     * strlen(homedir) + 13 + 1
     * strlen(homedir) + 14
     */
      
    config_file = rrp_malloc(strlen(homedir) + 14);
    strcpy(config_file, homedir);
    strcat(config_file, "/.radreplayrc");

    debugPrint("Checking config file %s\n", config_file);

    if (stat(config_file, &st) == 0)
      return config_file;

    free(config_file);
  }

  if (stat(DEFCONFFILE, &st) == 0)
  {
    config_file = rrp_strdup(DEFCONFFILE);
    return config_file;
  }

  return NULL;
}

int read_config(char *config_file, struct config *config)
{
  FILE *fp;
  char *buffer, *tmpkey, *tmpval;
  int buflen = 1024;


  debugPrint("Parsing config file %s\n", config_file);
  fp = fopen(config_file, "r");
  if (fp == NULL)
    return 1;

  buffer = rrp_malloc(buflen);
  tmpkey = rrp_malloc(33);
  tmpval = rrp_malloc(991);

  while (fgets(buffer, buflen, fp) != NULL)
  {
    /* skip empty lines, and comment lines */
    if (*buffer == '\n' || *buffer == '\r' || *buffer == '\0' || *buffer == '#')
      continue;

    if (sscanf(buffer, "%32s = %990s", tmpkey, tmpval) < 2)
    {
      debugPrint("Could not parse line: %s\n", buffer);
      continue;
    }

    if (strcmp(tmpkey, "server") == 0 && config->server_host == NULL)
      config->server_host = rrp_strdup(tmpval);
    else if (strcmp(tmpkey, "port") == 0 && config->server_port == 0)
      config->server_port = atoi(tmpval);
    else if (strcmp(tmpkey, "ignore") == 0 && config->ignore_string == NULL)
      config->ignore_string = rrp_strdup(tmpval);
    else if (strcmp(tmpkey, "dictionary") == 0 && config->dictionary == NULL)
      config->dictionary = rrp_strdup(tmpval);
    else
    {
      debugPrint("Unknown key '%s', skipping\n", tmpkey);
    }
  }

  free(buffer);
  free(tmpkey);
  free(tmpval);

  fclose(fp);
  free(config_file);
  return 0;
}
