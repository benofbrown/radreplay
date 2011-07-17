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

#include <stdint.h>

/* DECLARATIONS */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s 
{
  time_t ts_sec;         /* timestamp seconds */
  time_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
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
  uint16_t type;
} eth_header;

typedef struct ip_header_s
{
  unsigned char version_len;
  unsigned char dsf;
  uint16_t total_len;
  uint16_t id;
  uint16_t flags_frag;
  unsigned char ttl;
  unsigned char proto;
  uint16_t chksum;
  uint32_t src;
  uint32_t dst;
} ip_header;

typedef struct udp_header_s
{
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t chksum;
} udp_header;

/* RADIUS packet header */
typedef struct rad_header_s
{
  unsigned char code;
  unsigned char id;
  uint16_t len;
  unsigned char authenticator[16];
} rad_header;

/* Packet stuff */
typedef struct packet_cache_s
{
  pcaprec_hdr_t recheader;
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
  uint32_t vendor_id;
  struct attr_entry_s *next;
} attr_entry;

typedef struct value_entry_s
{
  int id;
  int attr_id;
  uint32_t vendor;
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
  uint32_t vendor;
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
void hexDump (void *data, uint32_t len);
void hexPrint (void *data, uint32_t len);
void *rrp_malloc(size_t size);
void *rrp_strdup(const char *string);

/* from packet.c */
packet_cache *create_pcache (packet_cache *old);
packet_cache *add_pcache(packet_cache **start, pcaprec_hdr_t *recheader, ip_header *ip, udp_header *udp, rad_header *rad, size_t attrlen);
void free_pcache(packet_cache *pc);
void free_all_pcache(packet_cache *pc);
packet_cache *find_pcache(packet_cache *pc, uint32_t src, uint16_t src_port, unsigned char id, unsigned char code);
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
avp *find_attribute(avp *attr, uint32_t vendor, unsigned char code);
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
