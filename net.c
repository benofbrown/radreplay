#include <stdio.h>

#include <radiusclient-ng.h>

#include "rad-pcap-test.h"

packet_cache *test_packet(char *server_host, int server_port, packet_cache *req)
{
  packet_cache *res = create_pcache(NULL);

  debugPrint("Sending packet id %02x to %s:%d\n", req->rad.id, server_host, server_port);

  return res;
}
