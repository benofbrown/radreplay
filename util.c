#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "rad-pcap-test.h"

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
