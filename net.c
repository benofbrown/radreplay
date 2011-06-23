#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "rad-pcap-test.h"

packet_cache *send_packet(char *server_host, int server_port, packet_cache *req)
{
  int fd = 0, rc = 0;
  fd_set fds;
  struct sockaddr_in addr;
  unsigned char *raw = NULL, *r = NULL;
  packet_cache *res = NULL;
  size_t rawsize = sizeof(rad_header) + req->attrlen;
  unsigned char response[65535];
  ssize_t reclen = 0;
  struct timeval timeout;

  debugPrint("Sending packet id %02x to %s:%d\n", req->rad.id, server_host, server_port);

  raw = malloc(rawsize);
  if (!raw)
    die("Could not malloc %d for raw\n", rawsize);

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(server_port);
  if (inet_aton(server_host, &(addr.sin_addr)) == 0)
    return NULL;


  if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    return res;
 
  r = raw;
  memcpy(r, &(req->rad), sizeof(req->rad));
  r += sizeof(req->rad);
  memcpy(r, req->attributes, req->attrlen);

  if (sendto(fd, raw, rawsize, 0, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == -1)
    return res;

  free(raw);
  FD_ZERO(&fds);
  FD_SET(fd, &fds);
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  rc = select(fd + 1, &fds, NULL, NULL, &timeout);
  debugPrint("Select returned %d\n", rc);
  if (rc <= 0)
    return res;

  if ((reclen = recvfrom(fd, &response, sizeof(response), 0, NULL, NULL)) == -1)
    return res;

printf("START RESPONSE\n");
hexDump(response, reclen);
printf("END RESPONSE\n");

  /* check the len, should be at least 20 (code, id and authenticator) */
  if (reclen < 20)
    return res;

  res = create_pcache(NULL);
  r = response;
  memcpy(&(res->rad), r, sizeof(rad_header));
  r += sizeof(rad_header);
  res->attrlen = reclen - sizeof(rad_header);
  if (res->attrlen > 0)
  {
    res->attributes = malloc(res->attrlen);
    if (!res->attributes)
     die("Could not allocate memory for res->attributes\n");

    memcpy(res->attributes, r, res->attrlen);
  }

  return res;
}
