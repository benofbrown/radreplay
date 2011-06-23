#include <string.h>
#include <radiusclient-ng.h>
#include "rad-pcap-test.h"

/* returns 0 on a match, 1 on a near-match, 2 on a miss */
int check_payload (void *rcv, packet_cache *reference, packet_cache *response)
{
  rc_handle *radiusclient = (rc_handle *) rcv;

  /* check radius code, it's a small number so lowest overhead */
  if (reference->rad.code != response->rad.code)
    return 1;

  /* simple initial check, see if the attrs are the same length */
  if (reference->attrlen != response->attrlen)
    return 2;

  /* another simple one, do the attributes match? */
  if (memcmp(reference->attributes, response->attributes, response->attrlen) != 0)
    return 2;

  return 0; 
}
