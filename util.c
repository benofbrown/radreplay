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
#include <stdarg.h>
#include <string.h>

#include "radreplay.h"

char debug;

/* Added for convenience */
void die (char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
  exit(1);
}

void debugPrint (char *format, ...)
{
  va_list ap;

  if (!debug)
    return;

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
}

void hexDump (void *data, guint32 len)
{
  guint32 i = 0;
  unsigned int line = 0;
  unsigned char *str = (unsigned char *) data;

  for (i = 0; i < len; i++)
  {
    if (i % 16 == 0)
    {
      printf("%s\t0x%04x:  ", line ? "\n" : " ", line * 16);
      line++;
    }
    
    printf("%02x%s", str[i], i % 2 ? " " : "");
  }
  printf("\n");
}

void hexPrint (void *data, guint32 len)
{
  guint32 i = 0;
  unsigned char *str = (unsigned char *) data;

  printf("0x");
  for (i = 0; i < len; i++)
    printf("%02x", str[i]);
  
}

void *rrp_malloc(size_t size)
{
  void *p = malloc(size);
  if (!p)
    die("Could not allocate %u bytes\n", size);

  return p;
}

void *rrp_strdup(const char *string)
{
  void *p = strdup(string);
  if (!p)
    die("Could not duplicate %s\n", string);

  return p;
}
