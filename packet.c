#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "rad-pcap-test.h"

static packet_cache *create_pcache (packet_cache *old)
{
  packet_cache *new = malloc(sizeof(packet_cache));
  if (!new)
    die("Could not allocate memory for new pcache\n");

  if (old)
    new->next = old;
  else
    new->next = NULL;

  new->attributes = NULL;

  return new;
}

packet_cache *add_pcache(packet_cache *old, ip_header *ip, udp_header *udp, rad_header *rad, size_t attrlen)
{
  packet_cache *pc = create_pcache(old);

  memcpy(&(pc->ip),  ip,  sizeof(ip_header));
  memcpy(&(pc->udp), udp, sizeof(udp_header));
  memcpy(&(pc->rad), rad, sizeof(rad_header));
  pc->attrlen = attrlen;

  return pc;
}

/* Doesn't free the whole thing, just the attributes.
   Otherwise could break the linked list leaving orphans.
*/
void free_pcache(packet_cache *pc)
{
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
}

void free_all_pcache(packet_cache *pc)
{
  if (pc->next)
    free_all_pcache(pc->next);

  free_pcache(pc);
  free(pc);
}

packet_cache *find_pcache(packet_cache *pc, guint16 src_port, guint16 dst_port, unsigned char id, unsigned char code)
{
  packet_cache *found = NULL;
  packet_cache *iter = NULL;

  for (iter = pc; iter->next != NULL; iter++)
  {
    if (iter->udp.src_port == src_port 
        && iter->udp.dst_port == dst_port
        && iter->rad.id == id
        && iter->rad.code == code)
    {
      found = iter;
      break;
    } 
  }

  return found;
}

/* for debugging */
void dump_pcache(packet_cache *pc)
{
  struct in_addr in;

  in.s_addr = pc->ip.src;
  printf("%s:%d ", inet_ntoa(in), htons(pc->udp.src_port));
  in.s_addr = pc->ip.dst;
  printf("-> %s:%d RADIUS id %02x (%d) code %02x (%d)\n",
          inet_ntoa(in), htons(pc->udp.dst_port), pc->rad.id, pc->rad.id,
          pc->rad.code, pc->rad.code);

  if (pc->attributes)
    hexDump(pc->attributes, pc->attrlen);
}

void dump_all_pcache(packet_cache *pc)
{
  if (pc->next)
    dump_all_pcache(pc->next);

  dump_pcache(pc);
}
