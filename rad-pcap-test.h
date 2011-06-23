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

/* 
 *  Structures for the header data. Unfortunately we can't lump it all together
 *  as struct padding ruins it for us.
 */

typedef struct eth_header_s
{
  unsigned char dst_mac[6];
  unsigned char src_mac[6];
  guint16 type;
} eth_header;

typedef struct ip_header_s
{
  unsigned char version_len;
  unsigned char dsf;
  guint16 total_len;
  guint16 id;
  guint16 flags_frag;
  unsigned char ttl;
  unsigned char proto;
  guint16 chksum;
  guint32 src;
  guint32 dst;
} ip_header;

typedef struct udp_header_s
{
  guint16 src_port;
  guint16 dst_port;
  guint16 len;
  guint16 chksum;
} udp_header;

/* RADIUS packet header */
typedef struct rad_header_s
{
  unsigned char code;
  unsigned char id;
  guint16 len;
  unsigned char authenticator[16];
} rad_header;

/* FUNCTIONS */

/* From util.c */
void die (char *format, ...);
void debugPrint (char *format, ...);
void hexDump (void *data, guint32 len);
