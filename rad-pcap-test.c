#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* defined here to avoid needing glib.h */
typedef unsigned int guint32;
typedef short unsigned int guint16;
typedef int gint32;


/* Taken from http://wiki.wireshark.org/Development/LibpcapFileFormat */
typedef struct pcap_hdr_s 
{
  guint32 magic_number;   /* magic number */
  guint16 version_major;  /* major version number */
  guint16 version_minor;  /* minor version number */
  gint32  thiszone;       /* GMT to local correction */
  guint32 sigfigs;        /* accuracy of timestamps */
  guint32 snaplen;        /* max length of captured packets, in octets */
  guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s 
{
  guint32 ts_sec;         /* timestamp seconds */
  guint32 ts_usec;        /* timestamp microseconds */
  guint32 incl_len;       /* number of octets of packet saved in file */
  guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

/* end of Taken from http://wiki.wireshark.org/Development/LibpcapFileFormat */


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
  char *debug;

  debug = getenv("DEBUG");
  if (!debug)
    return;

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
}

void hexDump (unsigned char *str, guint32 len)
{
  guint32 i = 0;
  unsigned int line = 0;

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

typedef struct buffer_s
{
  unsigned char *buffer;
  guint32 size;
} buffer; 

typedef struct udp_header_s
{
  unsigned char dst_mac[6];
  unsigned char src_mac[6];
  guint16 type;
  unsigned char version_len;
  unsigned char dsf;
  guint16 total_len;
  guint16 id;
  guint16 flags_frag;
  unsigned char ttl;
  unsigned char proto;
  guint16 chksum;
  guint32 src_ip;
  guint32 dst_ip;
  guint16 src_port;
  guint16 dst_port;
  guint16 udp_len;
  guint16 udp_chksum;
} udp_header;


int main (void)
{
  FILE *fp = NULL;
  const char *file = "/tmp/test2.pcap";
  pcap_hdr_t header;
  pcaprec_hdr_t recheader;
  size_t read = 0;
  udp_header udp;
  buffer buf;

  buf.buffer = NULL;
  buf.size = 0;

  /* check our sizes are right */
  if (sizeof(guint32) != 4 || sizeof(guint16) != 2 || sizeof(gint32) != 4)
    die("One or more of guint32, guint16 or gint32 is not the size we expect it to be\n");

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


    if (recheader.incl_len != recheader.orig_len)
    {
      printf("Packet truncated by capture - skipping\n");
      continue;
    }

    /* RADIUS packets are AT LEAST 42 bytes long */
    if (recheader.incl_len <= 42)
    {
      printf("packet too short - skipping\n");
      continue;
    }

    /* buffer will contain the udp payload, the header will go
      in to our struct */
    if (buf.size < recheader.incl_len - sizeof(udp))
    {
      if (buf.buffer)
        free(buf.buffer);

      buf.buffer = malloc(recheader.incl_len - sizeof(udp));
      if (!buf.buffer)
        die("Could not malloc buf.buffer\n");

      buf.size = recheader.incl_len - sizeof(udp);
    }


    /* read in udp header */
    read = fread(&udp, 1, sizeof(udp), fp);
    if (read != sizeof(udp))
    {
      printf("Failed to read enough of the packet - skipping\n");
      continue;
    }

    if (udp.proto != 0x11)
    {
      printf("Packet is type %x, not UDP - skipping\n", udp.proto);
      continue;
    }

    fread(buf.buffer, recheader.incl_len - sizeof(udp), 1, fp);
    hexDump(buf.buffer, recheader.incl_len - sizeof(udp));
  }

  free(buf.buffer);
  fclose(fp);
  return 0;
}
