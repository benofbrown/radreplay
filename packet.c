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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "radreplay.h"

extern char debug;

packet_cache *create_pcache (packet_cache *old)
{
  packet_cache *new = rrp_malloc(sizeof(packet_cache));

  memset(new, 0, sizeof(packet_cache));
  if (old)
    new->next = old;
  else
    new->next = NULL;

  new->attributes = NULL;

  return new;
}

packet_cache *add_pcache(packet_cache **start, pcaprec_hdr_t *recheader, ip_header *ip, udp_header *udp, rad_header *rad, size_t attrlen)
{
  packet_cache *pc = NULL, *iter = NULL;

  for (iter = *start; iter != NULL; iter = iter->next)
  {
    if (iter->used == 0)
    {
      pc = iter;
      pc->used = 1;
      break;
    }
  }

  if (!pc)
  {
    pc = create_pcache(*start);
    *start = pc;
  }

  memcpy(&(pc->recheader), recheader,  sizeof(pcaprec_hdr_t));
  memcpy(&(pc->ip),        ip,         sizeof(ip_header));
  memcpy(&(pc->udp),       udp,        sizeof(udp_header));
  memcpy(&(pc->rad),       rad,        sizeof(rad_header));
  pc->attrlen = attrlen;
  pc->used = 1;

  return pc;
}

/* Doesn't free the whole thing, just the attributes.
   Otherwise could break the linked list leaving orphans.
*/
void free_pcache(packet_cache *pc)
{
  debugPrint("Freeing packet cache src_port %04x dst_port %04x id %02x code %02x\n",
              pc->udp.src_port, pc->udp.dst_port, pc->rad.id, pc->rad.code);

  if (pc->attributes)
  {
    free(pc->attributes); 
    pc->attributes = NULL;
  }

  /* some defaults to stop it being found by find_pcache */
  pc->udp.src_port = 0;
  pc->udp.dst_port = 0;
  pc->rad.id = 0;
  pc->rad.code = 0;
  pc->used = 0;
}

void free_all_pcache(packet_cache *pc)
{
  if (pc->next)
    free_all_pcache(pc->next);

  free_pcache(pc);
  free(pc);
}

packet_cache *find_pcache(packet_cache *pc, guint32 src, guint16 src_port, unsigned char id, unsigned char code)
{
  packet_cache *found = NULL;
  packet_cache *iter = NULL;
  struct in_addr in;

  in.s_addr = src;
  debugPrint("Looking for: %s:%u id %02x code %02x\n",
            inet_ntoa(in), htons(src_port), id, code);

  for (iter = pc; iter != NULL; iter = iter->next)
  {
    if (iter->used == 0)
      continue;

    if (debug)
      in.s_addr = iter->ip.src;
    debugPrint("Checking:    %s:%u id %02x code %02x\n",
      inet_ntoa(in), iter->udp.src_port, iter->rad.id, iter->rad.code);

    if (iter->udp.src_port == src_port 
        && iter->ip.src == src
        && iter->rad.id == id
        && iter->rad.code == code)
    {
      found = iter;
      break;
    } 
  }

  return found;
}

void dump_pcache(packet_cache *pc, char dumpAttrs)
{
  struct in_addr in;
  struct tm time;
  char timestr[9];

  memset(&time, 0, sizeof(time));

  localtime_r(&(pc->recheader.ts_sec), &time);
  strftime((char *) &timestr, 9, "%H:%M:%S", &time);
  in.s_addr = pc->ip.src;
  printf("%s.%06u %s:%d ", timestr, (unsigned int) pc->recheader.ts_usec,
           inet_ntoa(in), htons(pc->udp.src_port));
  in.s_addr = pc->ip.dst;
  printf("-> %s:%d RADIUS id %02x (%d) code %02x (%d):",
          inet_ntoa(in), htons(pc->udp.dst_port), pc->rad.id, pc->rad.id,
          pc->rad.code, pc->rad.code);

  if (pc->attributes && dumpAttrs)
  {
    printf("\n");
    hexDump(pc->attributes, pc->attrlen);
  }
}

void dump_all_pcache(packet_cache *pc)
{
  if (pc->next)
    dump_all_pcache(pc->next);

  dump_pcache(pc, 1);
}
