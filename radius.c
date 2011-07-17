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
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "radreplay.h"

typedef struct entry_s
{
  char *value;
  size_t len;
} entry_t;

static entry_t *add_entry(size_t len)
{
  entry_t *entry = rrp_malloc(sizeof(entry_t));
  entry->value = rrp_malloc(len);
  entry->len = len - 1;

  return entry;
}

static void free_entry(entry_t *entry)
{
  if (entry == NULL)
    return;

  if (entry->value)
    free(entry->value);

  free(entry);
}

static int parse_line(const char *line, entry_t **entries)
{
  entry_t **entry;
  const char *start = line;
  const char *end, *c, *check;
  const char *endings = " \t\r\n";
  size_t len = 0;
  int parsed = 0;

  for (entry = entries; *entry != NULL; entry++)
  {
    while (isspace(*start) && *start != '\0' && *start != '\r' && *start != '\n')
      start++;

    if (*start == '\0')
      return 0;

    end = NULL;
    c = endings;
    while (end == NULL && *c != '\0')
    {
      end = strchr(start, *c);
      c++;
    }
  
    if (end == NULL)
      return 0;

    check = strchr(start, '\t');
    if (check != NULL && check < end)
      end = check;

    len = end - start < (*entry)->len ? end - start : (*entry)->len;
    memcpy((*entry)->value, start, len);
    (*entry)->value[len] = '\0';
    start = end;
    parsed++;
  }

  return parsed;
}

static void free_attr(attr_entry *attr)
{
  if (attr == NULL)
    return;

  if (attr->next)
    free_attr(attr->next);

  if (attr->name)
    free(attr->name);

  free(attr);
}

avp *parse_attributes (avp *old, size_t datalen, unsigned char *data)
{
  avp *new = malloc(sizeof(avp));
  unsigned char *d = data;
  size_t padding = 0;

  if (!new)
    die("Could not allocate memory for avp\n");

  if (old)
    new->next = old;
  else
    new->next = NULL;

  /* len and code are 2 chars, write them in to place */
  memcpy(new, data, 2);
  d += 2;

  new->vendor = 0;

  /* Vendor Specific */
  if (new->code == 26)
  {
    uint32_t vendor = 0;
    memcpy(&vendor, d, sizeof(vendor));
    new->vendor = htonl(vendor);
    d += sizeof(vendor);
    memcpy(new, d, 2);
    d += 2;
    padding = sizeof(vendor) + 2;
  }

  new->value = malloc(new->len - 2);
  if (!new->value)
    die("Could not allocate %d bytes for avp value\n", new->len - 2);

  memcpy(new->value, d, new->len - 2);

  if (datalen - (new->len + padding) > 0)
  {
    d += (new->len - 2);
    new = parse_attributes(new, datalen - (new->len + padding), d);
  }

  return new;
}

void dump_attributes(dict_entry *dict, avp *attr)
{
  if (attr->next)
    dump_attributes(dict, attr->next);

  printf("  ");
  print_attr_name(dict, attr);
  printf(" = ");
  print_attr_val(dict, attr);
  printf("\n");
}

void free_attributes(avp *attr)
{
  if (attr->next)
    free_attributes(attr->next);

  free(attr->value);
  free(attr);
}

avp *find_attribute(avp *attr, uint32_t vendor, unsigned char code)
{
  avp *iter = NULL;

  for (iter = attr; iter != NULL; iter = iter->next)
  {
    if (iter->code == code && iter->vendor == vendor)
      return iter;
  }

  return NULL;
}

dict_entry *read_dictionary(dict_entry *old, const char *file)
{
  FILE *fp = NULL;
  char *buffer = NULL;
  size_t buflen = 1280;
  int vendorid = 0;
  attr_entry *tmp_attr = NULL;
  vendor_entry *tmp_vendor = NULL;
  value_entry *tmp_value = NULL;
  char *tmpchar = NULL;
  dict_entry *dict = NULL;
  entry_t *tmp_name = NULL, *tmp_type = NULL, *tmp_id = NULL, *tmp_value_str = NULL;
  entry_t **entries = NULL;

  if ((fp = fopen(file, "r")) == NULL)
    return NULL;

  if (old)
    dict = old;
  else
  {
    dict = rrp_malloc(sizeof(dict_entry));

    dict->attr = NULL;
    dict->vendor = NULL;
    dict->value = NULL;
    dict->ignore = NULL;
  }

  buffer = rrp_malloc(buflen + 1);

  tmp_name = add_entry(33);
  tmp_type = add_entry(17);
  tmp_id = add_entry(9);
  tmp_value_str = add_entry(1024);
  entries = rrp_malloc(sizeof(entry_t *) * 4);

  while (fgets(buffer, buflen, fp) != NULL)
  {
    /* skip empty lines, and comment lines */
    if (*buffer == '\n' || *buffer == '\r' || *buffer == '\0' || *buffer == '#')
      continue;

    /* strip out comments */
    if ((tmpchar = strchr(buffer, '#')) != NULL)
      tmpchar = '\0';

    if (strncmp(buffer, "ATTRIBUTE", 9) == 0)
    {
      tmpchar = buffer + 9;
      entries[0] = tmp_name;
      entries[1] = tmp_id;
      entries[2] = tmp_type;
      entries[3] = NULL;
      if (parse_line(tmpchar, entries) < 3)
      {
        debugPrint("Couldn't scan line: %s", tmpchar);
        continue;
      }

      tmp_attr = rrp_malloc(sizeof(attr_entry));

      tmp_attr->next = NULL;
      tmp_attr->id = atoi(tmp_id->value);
      tmp_attr->vendor_id = vendorid;
      tmp_attr->name = rrp_strdup(tmp_name->value);

      if (strncmp(tmp_type->value, "string", 6) == 0)
        tmp_attr->type = ATTR_TYPE_STRING;
      else if (strncmp(tmp_type->value, "integer", 7) == 0)
        tmp_attr->type = ATTR_TYPE_INT;
      else if (strncmp(tmp_type->value, "ipaddr", 6) == 0)
        tmp_attr->type = ATTR_TYPE_IPADDR;
      else if (strncmp(tmp_type->value, "ipv6addr", 8) == 0)
        tmp_attr->type = ATTR_TYPE_IPV6ADDR;
      else if (strncmp(tmp_type->value, "ipv6prefix", 10) == 0)
        tmp_attr->type = ATTR_TYPE_IPV6PREFIX;
      else if (strncmp(tmp_type->value, "octets", 6) == 0)
        tmp_attr->type = ATTR_TYPE_OCTECT;
      else
      {
        debugPrint("unknown attribute type %s. Skipping line: %s", tmp_type->value, buffer);
        free_attr(tmp_attr);
        continue;
      }

      debugPrint("name: %s id: %d type: %d vendor-id: %d\n", tmp_attr->name, tmp_attr->id, tmp_attr->type, tmp_attr->vendor_id);

      if (dict->attr)
        tmp_attr->next = dict->attr;

      dict->attr = tmp_attr;
    }
    else if (strncmp(buffer, "VENDOR", 6) == 0)
    {
      tmpchar = buffer + 6;
      entries[0] = tmp_name;
      entries[1] = tmp_id;
      entries[2] = NULL;
      if (parse_line(tmpchar, entries) < 2)
      {
        debugPrint("Couldn't parse VENDOR line: %s", buffer);
        continue;
      }

      tmp_vendor = rrp_malloc(sizeof(vendor_entry));

      tmp_vendor->next = NULL;
      tmp_vendor->name = rrp_strdup(tmp_name->value);
      tmp_vendor->id = strtoull(tmp_id->value, NULL, 10);
      vendorid = tmp_vendor->id;

      debugPrint("Vendor %s id: %u\n", tmp_vendor->name, tmp_vendor->id);

      if (dict->vendor)
        tmp_vendor->next = dict->vendor;

      dict->vendor = tmp_vendor;
    }
    else if (strncmp(buffer, "VALUE", 5) == 0)
    {
      tmpchar = buffer + 5;
      entries[0] = tmp_name;
      entries[1] = tmp_value_str;
      entries[2] = tmp_id;
      entries[3] = NULL;
      if (parse_line(tmpchar, entries) < 3)
      {
        debugPrint("Couln't parse VALUE line: %s", buffer);
        continue;
      }

      tmp_value = rrp_malloc(sizeof(value_entry));

      tmp_value->next = NULL;
      tmp_value->id = atoi(tmp_id->value);
      tmp_value->value = rrp_strdup(tmp_value_str->value);
      tmp_value->attr_id = find_attribute_id(dict->attr, tmp_name->value);
      tmp_value->vendor = vendorid;

      debugPrint("Value: vendor: %u id: %d attr_id: %d value: %s name: %s\n",
                  tmp_value->vendor, tmp_value->id, tmp_value->attr_id,
                  tmp_value->value, tmp_name);

      if (dict->value)
        tmp_value->next = dict->value;

      dict->value = tmp_value;  
    }
    else if (strncmp(buffer, "$INCLUDE", 8) == 0)
    {
      tmpchar = buffer + 8;
      entries[0] = tmp_value_str;
      entries[1] = NULL;
      if (parse_line(tmpchar, entries) < 1)
      {
        debugPrint("Could not parse $INCLUDE line: %s\n", buffer);
        continue;
      }

      dict = read_dictionary(dict, tmp_value_str->value);
      debugPrint("$INCLUDED %s\n", tmp_value_str);
    }
    else if (strncmp(buffer, "END-VENDOR", 10) == 0)
      vendorid = 0;
  }
  fclose(fp);
  free(buffer);
  free_entry(tmp_name);
  free_entry(tmp_type);
  free_entry(tmp_id);
  free_entry(tmp_value_str);
  free(entries);
  return dict;
}

int find_attribute_id(attr_entry *attr, const char *name)
{
  attr_entry *iter = NULL;

  for (iter = attr; iter != NULL; iter = iter->next)
    if (strcmp(iter->name, name) == 0)
      return iter->id;

  return 0;
}


attr_entry *find_attribute_entry(dict_entry *dict, const char *name)
{
  attr_entry *iter = NULL;

  for (iter = dict->attr; iter != NULL; iter = iter->next)
    if(strcmp(iter->name, name) == 0)
      return iter;

  return NULL;
}


static void free_vendor(vendor_entry *vendor)
{
  if (vendor == NULL)
    return;

  if (vendor->next)
    free_vendor(vendor->next);

  free(vendor->name);
  free(vendor);
}

static void free_value(value_entry *value)
{
  if (value == NULL)
    return;

  if (value->next)
    free_value(value->next);

  free(value->value);
  free(value);
}

void free_dictionary(dict_entry *dict)
{
  if (dict == NULL)
    return;

  free_attr(dict->attr);
  free_vendor(dict->vendor);
  free_value(dict->value);
  free_attr(dict->ignore);
  free(dict);
  dict = NULL;
}

static attr_entry *get_attr(dict_entry *dict, unsigned long long vendor, int id)
{
  attr_entry *attr = NULL;

  for (attr = dict->attr; attr != NULL; attr = attr->next)
    if (attr->vendor_id == vendor && attr->id == id)
      return attr;

  return NULL;
}

static void print_attr_string_val(avp *attr)
{
  size_t i = 0;
  unsigned char *c;

  for (i = 0, c = attr->value; i < (attr->len - 2); i++, c++)
    putchar(*c);
}

void print_attr_name(dict_entry *dict, avp *attr)
{
  attr_entry *dict_attr = NULL;

  dict_attr = get_attr(dict, attr->vendor, attr->code);
  if (!dict_attr)
  {
    printf("Unknown Attribute");
    return;
  }

  printf("%s", dict_attr->name);
}

static void print_index_val(dict_entry *dict, avp *attr)
{
  value_entry *value = NULL;
  uint32_t id = 0, tmpint = 0;

  memcpy(&tmpint, attr->value, sizeof(tmpint));
  id = htonl(tmpint);

  for (value = dict->value; value != NULL; value = value->next)
    if (value->attr_id == attr->code && value->vendor == attr->vendor
        && value->id == id)
    {
      printf("%s", value->value);
      return;
    }

  printf("%u", id);
}

void print_attr_val(dict_entry *dict, avp *attr)
{
  attr_entry *dict_attr = NULL;

  dict_attr = get_attr(dict, attr->vendor, attr->code);
  if (!dict_attr)
  {
    hexPrint(attr->value, attr->len - 2);
    return;
  }

  if (dict_attr->type == ATTR_TYPE_STRING)
    print_attr_string_val(attr);
  else if (dict_attr->type == ATTR_TYPE_INT)
  {
    print_index_val(dict, attr);
  }
  else if (dict_attr->type == ATTR_TYPE_IPADDR)
  {
    char *ipaddr = NULL;
    struct in_addr in;

    ipaddr = rrp_malloc(INET_ADDRSTRLEN + 1);

    memset(ipaddr, 0, INET_ADDRSTRLEN);
    memcpy(&in.s_addr, attr->value, attr->len - 2);

    if (inet_ntop(AF_INET, &in, ipaddr, INET_ADDRSTRLEN) == NULL)
      die("inet_ntop failed\n");

    printf("%s", ipaddr);
    free(ipaddr);
  }
  else if (dict_attr->type == ATTR_TYPE_IPV6ADDR)
  {
    char *ip6addr = NULL;
    struct in6_addr in6;

    ip6addr = rrp_malloc(INET6_ADDRSTRLEN + 1);

    memset(ip6addr, 0, INET6_ADDRSTRLEN);
    memcpy(&in6.s6_addr, attr->value, attr->len - 2);

    if (inet_ntop(AF_INET6, &in6, ip6addr, INET6_ADDRSTRLEN) == NULL)
      die("inet_ntop failed\n");

    printf("%s", ip6addr);
    free(ip6addr);
  }
  else
  {
    hexPrint(attr->value, attr->len - 2);
  }
}
