#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rad-pcap-test.h"


int main (void)
{
  FILE *fp = NULL;
  const char *file = "/tmp/test2.pcap";
  pcap_hdr_t header;
  pcaprec_hdr_t recheader;
  size_t read = 0;
  eth_header eth;
  ip_header ip;
  udp_header udp;
  rad_header rad;
  unsigned char *attributes = NULL;
  long nextpos = 0;
  size_t header_size = sizeof(ip) + sizeof(eth) + sizeof(udp) + sizeof(rad);
  struct in_addr in;

  /* check our sizes are right */
  if (sizeof(guint32) != 4 || sizeof(guint16) != 2 || sizeof(gint32) != 4)
    die("One or more of guint32, guint16 or gint32 is not the size we expect it to be\n");

  if (header_size != 62)
    die("The header structs are not the expected size, this will not work\n");

  if ((fp = fopen(file, "r")) == NULL)
    die("Cannot open %s\n", file);

  read = fread(&header, 1, sizeof(header), fp);
  if (read != sizeof(header))
    die("Could not read header, is %s a pcap file?\n", file);
  
  debugPrint("0x%x\n%u\n%u\n%d\n%u\n%u\n%u\n",
    header.magic_number,
    header.version_major,
    header.version_minor,
    header.thiszone,
    header.sigfigs,
    header.snaplen,
    header.network);

  if (header.magic_number != 0xa1b2c3d4)
    die("unsupported magic number\n");

  if (header.network != 1)
    die("unsupported network\n");

  if (header.version_major != 2 || header.version_minor != 4)
    fprintf(stderr, "This was not written for version %d.%d files, this may not work correctly\n",
      header.version_major, header.version_minor);

  attributes = malloc(header.snaplen);
  if (!attributes)
    die("Could not malloc for attributes");

  while (!feof(fp))
  {
    read = fread(&recheader, 1, sizeof(recheader), fp);
    if (read != sizeof(recheader))
      break;

    debugPrint("ts_sec = %u\nts_usec = %u\nincl_len = %u\norig_len = %u\n",
      recheader.ts_sec,
      recheader.ts_usec,
      recheader.incl_len,
      recheader.orig_len);

    nextpos = ftell(fp) + recheader.incl_len;

    if (recheader.incl_len != recheader.orig_len)
    {
      printf("Packet truncated by capture - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    /* RADIUS packets are AT LEAST 42 bytes long */
    if (recheader.incl_len <= 42)
    {
      printf("packet too short - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    /* read in ethernet header */
    read = fread(&eth, 1, sizeof(eth), fp);
    if (read != sizeof(eth))
    {
      printf("Failed to read ethernet header - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    if (eth.type != 8)
    {
      printf("Packet is not an IP packet - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    /* read in IP header */
    read = fread(&ip, 1, sizeof(ip), fp);
    if (read != sizeof(ip))
    {
      printf("Failed to read IP header - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    if (ip.proto != 0x11)
    {
      printf("Packet is type %x, not UDP - skipping\n", ip.proto);
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    /* read in udp header */
    read = fread(&udp, 1, sizeof(udp), fp);
    if (read != sizeof(udp))
    {
      printf("Failed to read UDP header - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    /* read in RADIUS header */
    read = fread(&rad, 1, sizeof(rad), fp);
    if (read != sizeof(rad))
    {
      printf("Failed to read IP header - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }


    fread(attributes, recheader.incl_len - header_size, 1, fp);
    hexDump(attributes, recheader.incl_len - header_size);

    in.s_addr = ip.src;

    debugPrint("%s:%d -> %x:%d\n", inet_ntoa(in), htons(udp.src_port), ip.dst, htons(udp.dst_port));
    debugPrint("code: %x, len: %x (%d)\n", rad.code, htons(rad.len), htons(rad.len));
  }

  free(attributes);
  fclose(fp);
  return 0;
}
