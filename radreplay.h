/* DECLARATIONS */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* defined here to avoid needing glib.h */
typedef unsigned int guint32;
typedef short unsigned int guint16;
typedef int gint32;

/* Taken from radiusclient-ng */
#define  PW_ACCESS_REQUEST    1
#define  PW_ACCESS_ACCEPT     2
#define  PW_ACCESS_REJECT     3

/* RADIUS Dictionary */
#define ATTR_TYPE_STRING      1
#define ATTR_TYPE_INT         2
#define ATTR_TYPE_IPADDR      3
#define ATTR_TYPE_IPV6ADDR    4
#define ATTR_TYPE_IPV6PREFIX  5
#define ATTR_TYPE_OCTECT      6

/* STRUCTURES */

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

/* Packet stuff */
typedef struct packet_cache_s
{
  udp_header udp;
  ip_header ip;
  rad_header rad;
  unsigned char *attributes;
  size_t attrlen;
  char used;
  struct packet_cache_s *next;
} packet_cache;

typedef struct vendor_entry_s
{
  unsigned long long id;
  char *name;
  struct vendor_entry_s *next;
} vendor_entry;

typedef struct attr_entry_s
{
  int id;
  char *name;
  char type;
  guint32 vendor_id;
  struct attr_entry_s *next;
} attr_entry;

typedef struct value_entry_s
{
  int id;
  int attr_id;
  guint32 vendor;
  char *value;
  struct value_entry_s *next;
} value_entry;

typedef struct dict_entry_s
{
  attr_entry *attr;
  vendor_entry *vendor;
  value_entry *value;
  attr_entry *ignore;
} dict_entry;

typedef struct avp_s
{
  unsigned char code;
  unsigned char len;
  guint32 vendor;
  unsigned char *value;
  struct avp_s *next;
} avp;

struct config
{
  char *server_host;
  int server_port;
  char *dictionary;
  char *ignore_string;
};


/* FUNCTIONS */

/* From util.c */
void die (char *format, ...);
void debugPrint (char *format, ...);
void hexDump (void *data, guint32 len);
void hexPrint (void *data, guint32 len);
void *rrp_malloc(size_t size);
void *rrp_strdup(const char *string);

/* from packet.c */
packet_cache *create_pcache (packet_cache *old);
packet_cache *add_pcache(packet_cache **start, ip_header *ip, udp_header *udp, rad_header *rad, size_t attrlen);
void free_pcache(packet_cache *pc);
void free_all_pcache(packet_cache *pc);
packet_cache *find_pcache(packet_cache *pc, guint32 src, guint16 src_port, unsigned char id, unsigned char code);
void dump_pcache(packet_cache *pc, char dumpAttrs);
void dump_all_pcache(packet_cache *pc);

/* from net.c */
packet_cache *send_packet(char *server_host, int server_port, packet_cache *req);

/* from compare.c */
int check_payload (dict_entry *dict, packet_cache *reference, packet_cache *response);

/* from radius.c */
avp *parse_attributes (avp *old, size_t datalen, unsigned char *data);
void dump_attributes(dict_entry *dict, avp *attr);
void free_attributes(avp *attr);
avp *find_attribute(avp *attr, guint32 vendor, unsigned char code);
dict_entry *read_dictionary(dict_entry *old, const char *file);
void free_dictionary(dict_entry *dict);
void print_attr_name(dict_entry *dict, avp *attr);
void print_attr_val(dict_entry *dict, avp *attr);
int find_attribute_id(attr_entry *attr, const char *name);
attr_entry *find_attribute_entry(dict_entry *dict, const char *name);

/* from ignore.c */
void parse_ignore_string(dict_entry *dict, char *string);
int is_ignored(attr_entry *ignore, avp *check);

/* from config.c */
char *find_config_file(void);
int read_config(char *config_file, struct config *config);
