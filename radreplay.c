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
#include <unistd.h>
#include <time.h>

#include "radreplay.h"

extern char debug;

static void usage(char *name)
{
  fprintf(stderr, "usage: %s -f pcap_file [-h] [-s server_address] [-p server_port] [-d] [-r radius_dictionary]\n", name);
  exit(1);
}

int main (int argc, char **argv)
{
  struct config config;
  FILE *fp = NULL;
  char *file = NULL;
  pcap_hdr_t header;
  pcaprec_hdr_t recheader;
  size_t read = 0;
  eth_header eth;
  ip_header ip;
  udp_header udp;
  rad_header rad;
  long nextpos = 0;
  size_t header_size = sizeof(ip) + sizeof(eth) + sizeof(udp) + sizeof(rad);
  packet_cache *pc = NULL, *req = NULL, *start = NULL, *res = NULL;
  int opt;
  dict_entry *dict = NULL;
  unsigned int packets_sent = 0, packets_received = 0, matches = 0, attr_mismatches = 0, code_mismatches = 0;
  char default_server[] = "127.0.0.1";
  char default_dictionary[] = DEFDICTIONARY;
  char *config_file = NULL;
  struct timespec sleeptime;
  int rc = 0, send_attempts = 0;
  struct in_addr in;
  char ipaddr[INET_ADDRSTRLEN + 1];

  memset(&config, 0, sizeof(config));
  memset(&in, 0, sizeof(struct in_addr));

  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = 200000000;

  /* check our sizes are right */
  if (sizeof(uint32_t) != 4 || sizeof(uint16_t) != 2 || sizeof(int32_t) != 4)
    die("One or more of uint32_t, uint16_t or int32_t is not the size we expect it to be\n");

  if (header_size != 62)
    die("The header structs are not the expected size, this will not work\n");

  /* Sort out options */
  debug = 0;
  while ((opt = getopt(argc, argv, "hdf:s:p:r:i:")) != -1)
  {
    switch (opt)
    {
      case 'd':
        debug = 1;
        break;
      case 'f':
        file = rrp_strdup(optarg);
        break;
      case 'i':
        config.ignore_string = rrp_strdup(optarg);
        break;
      case 's':
        config.server_host = rrp_strdup(optarg);
        break;
      case 'p':
        config.server_port = atoi(optarg);
        break;
      case 'r':
        config.dictionary = rrp_strdup(optarg);
        break;
      case 'h':
        usage(argv[0]);
      default:
        usage(argv[0]);
    }
  }

  config_file = find_config_file();
  if (config_file)
  {
    if (read_config(config_file, &config) != 0)
      die("Could not read config file\n");
  }

  if (!config.server_host)
    config.server_host = default_server;

  if (config.server_port == 0)
    config.server_port = 1812;

  if (!config.dictionary)
    config.dictionary = default_dictionary;

  debugPrint("server = %s, port = %d, dictionary = %s\n", config.server_host, 
              config.server_port, config.dictionary);

  if (!file)
    usage(argv[0]);

  debugPrint("File: %s\n", file);

  if ((fp = fopen(file, "r")) == NULL)
    die("Cannot open %s\n", file);

  read = fread(&header, 1, sizeof(header), fp);
  if (read != sizeof(header))
    die("Could not read header, is %s a pcap file?\n", file);

  free(file);
  
  if (header.magic_number != 0xa1b2c3d4)
    die("unsupported magic number\n");

  if (header.network != 1)
    die("unsupported network\n");

  if (header.version_major != 2 || header.version_minor != 4)
    fprintf(stderr, "This was not written for version %d.%d files, this may not work correctly\n",
      header.version_major, header.version_minor);

  /* read dictionary */
  dict = read_dictionary(dict, config.dictionary);
  if (!dict)
    die("Could not read radius dictionary file %s\n", config.dictionary);

  if (config.dictionary != default_dictionary)
    free(config.dictionary);

  /* parse ignore string */
  if (config.ignore_string)
  {
    parse_ignore_string(dict, config.ignore_string);
    free(config.ignore_string);
  }

  while (!feof(fp))
  {

    fflush(stdout);

    read = fread(&recheader, 1, sizeof(recheader), fp);
    if (read != sizeof(recheader))
      break;

    nextpos = ftell(fp) + recheader.incl_len;

    if (recheader.incl_len != recheader.orig_len)
    {
      printf("Packet truncated by capture - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    /* RADIUS packets are AT LEAST 62 bytes long */
    if (recheader.incl_len < 62)
    {
      printf("packet too short (%d) - skipping\n", recheader.incl_len);
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
      printf("Failed to read attributes - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    /* 
      This may change in future, but for the moment we only care about
      Access-Request, Access-Accept and Access-Reject.
    */
    if (rad.code != PW_ACCESS_REQUEST && rad.code != PW_ACCESS_ACCEPT
        && rad.code != PW_ACCESS_REJECT)
    {
      printf("Not Access-Request, Access-Accept or Access-Reject - skipping\n");
      fseek(fp, nextpos, SEEK_SET);
      continue;
    }

    pc = add_pcache(&start, &recheader, &ip, &udp, &rad, recheader.incl_len - header_size);

    /* check if there are attributes */
    if (pc->attrlen > 0)
    {
      pc->attributes = rrp_malloc(pc->attrlen);

      read = fread(pc->attributes, 1, pc->attrlen, fp);
      if (read != pc->attrlen)
      {
        printf("Failed to read attributes - skipping\n");
        fseek(fp, nextpos, SEEK_SET);
        continue;
      }
    }

    /* if it's not a response our job is done for now */
    if (rad.code != PW_ACCESS_ACCEPT && rad.code != PW_ACCESS_REJECT)
      continue;

    req = find_pcache(start, ip.dst, udp.dst_port, rad.id, PW_ACCESS_REQUEST);
    if (!req)
    {
      printf("Request not found - skipping\n");
      continue;
    }

    /* send the packet and store the result */
    packets_sent++;
    while ((res = send_packet(config.server_host, config.server_port, req)) == NULL
            && send_attempts < 5)
    {
      send_attempts++;
      nanosleep(&sleeptime, NULL);
    }

    if (!res)
    {
      in.s_addr = req->ip.src;
      if (inet_ntop(AF_INET, &in, (char *) &ipaddr, INET_ADDRSTRLEN) == NULL)
        die("%s:%c: inet_ntop failed", __FILE__, __LINE__);

      printf("Did not get response sending packet id 0x%02x. Original source was %s:%d (ip id %u)\n",
              req->rad.id, ipaddr, htons(req->udp.src_port), htons(req->ip.id));
      continue;
    }

    packets_received++;

    if (debug)
      dump_pcache(res, 1);

    rc = check_payload(dict, pc, res);
    switch (rc)
    {
      case 0:
        matches++;
        printf("OK\n");
        break;
      case 1:
        code_mismatches++;
        printf("CODE MISMATCH: expected %u, got %u\n", pc->rad.code, res->rad.code);
        break;
      case 2:
        attr_mismatches++;
        break;
    }

    /* these packet caches are no longer needed, free them up for re-use */
    free_pcache(pc);
    free_pcache(req);

    /* reset res for next time */
    free_all_pcache(res);
    res = NULL;
  }

  if (config.server_host != default_server)
    free(config.server_host);

  free_dictionary(dict);
  free_all_pcache(start);
  fclose(fp);

  printf("STATISTICS: %u packets sent, %u responses.\n%u matched, %u attribute mismatches and %u response code mismatches\n",
          packets_sent, packets_received, matches, attr_mismatches, code_mismatches);
  return 0;
}
