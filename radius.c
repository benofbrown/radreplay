#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "rad-pcap-test.h"

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
    guint32 vendor = 0;
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

avp *find_attribute(avp *attr, guint32 vendor, unsigned char code)
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
  size_t buflen = 128;
  int vendorid = 0;
  attr_entry *tmp_attr = NULL;
  vendor_entry *tmp_vendor = NULL;
  value_entry *tmp_value = NULL;
  char *tmpchar = NULL, *tmp_id = NULL, *tmp_type = NULL, *tmp_name = NULL;
  char *tmp_value_str = NULL;
  dict_entry *dict = NULL;

  if (old)
    dict = old;
  else
  {
    if ((dict = malloc(sizeof(dict_entry))) == NULL)
      die("Could not allocate dict\n");

    dict->attr = NULL;
    dict->vendor = NULL;
    dict->value = NULL;
  }

  if ((buffer = malloc(buflen + 1)) == NULL)
    die("Could not allocate buffer\n");

  if ((tmp_id = malloc(9)) == NULL)
    die("Could not allocate tmp_id\n");

  if ((tmp_type = malloc(17)) == NULL)
    die("Could not allocate tmp_type\n");

  if ((tmp_name = malloc(33)) == NULL)
    die("Could not allocate tmp_name\n");

  if ((tmp_value_str = malloc(65)) == NULL)
    die("Could not allocate tmp_value_str\n");

  if ((fp = fopen(file, "r")) == NULL)
    return NULL;

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
      if (sscanf(buffer, "%*s%32s%8s%16s", tmp_name, tmp_id, tmp_type) < 3)
      {
        debugPrint("Couldn't scan line: %s", buffer);
        continue;
      }

      if ((tmp_attr = malloc(sizeof(attr_entry))) == NULL)
        die("Could not allocate tmp_attr\n");

      tmp_attr->next = NULL;
      tmp_attr->id = atoi(tmp_id);
      tmp_attr->vendor_id = vendorid;
      tmp_attr->name = strdup(tmp_name);

      if (strncmp(tmp_type, "string", 6) == 0)
        tmp_attr->type = ATTR_TYPE_STRING;
      else if (strncmp(tmp_type, "integer", 7) == 0)
        tmp_attr->type = ATTR_TYPE_INT;
      else if (strncmp(tmp_type, "ipaddr", 6) == 0)
        tmp_attr->type = ATTR_TYPE_IPADDR;
      else if (strncmp(tmp_type, "ipv6addr", 8) == 0)
        tmp_attr->type = ATTR_TYPE_IPV6ADDR;
      else if (strncmp(tmp_type, "ipv6prefix", 10) == 0)
        tmp_attr->type = ATTR_TYPE_IPV6PREFIX;
      else if (strncmp(tmp_type, "octets", 6) == 0)
        tmp_attr->type = ATTR_TYPE_OCTECT;
      else
      {
        debugPrint("unknown attribute type %s. Skipping\n", tmp_type);
        free(tmp_attr);
        continue;
      }

      debugPrint("name: %s id: %d type: %d vendor-id: %d\n", tmp_attr->name, tmp_attr->id, tmp_attr->type, tmp_attr->vendor_id);

      if (dict->attr)
        tmp_attr->next = dict->attr;

      dict->attr = tmp_attr;
    }
    else if (strncmp(buffer, "VENDOR", 6) == 0)
    {
      if(sscanf(buffer, "%*s%32s%8s", tmp_name, tmp_id) < 2)
      {
        debugPrint("Couldn't parse VENDOR line: %s", buffer);
        continue;
      }

      if ((tmp_vendor = malloc(sizeof(vendor_entry))) == NULL)
        die("Could not allocate tmp_vendor\n");

      tmp_vendor->next = NULL;
      tmp_vendor->name = strdup(tmp_name);
      tmp_vendor->id = strtoull(tmp_id, NULL, 10);
      vendorid = tmp_vendor->id;

      debugPrint("Vendor %s id: %u\n", tmp_vendor->name, tmp_vendor->id);

      if (dict->vendor)
        tmp_vendor->next = dict->vendor;

      dict->vendor = tmp_vendor;
    }
    else if (strncmp(buffer, "VALUE", 5) == 0)
    {
      if (sscanf(buffer, "%*s%32s%64s%8s", tmp_name, tmp_value_str, tmp_id) < 3)
      {
        debugPrint("Couln't parse VALUE line: %s", buffer);
        continue;
      }

      if ((tmp_value = malloc(sizeof(value_entry))) == NULL)
        die("Could not allocate tmp_value\n");

      tmp_value->next = NULL;
      tmp_value->id = atoi(tmp_id);
      tmp_value->value = strdup(tmp_value_str);
      tmp_value->attr_id = find_attribute_id(dict->attr, tmp_name);
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
      if (sscanf(buffer, "%*s%64s", tmp_value_str) < 1)
      {
        debugPrint("Could not parse $INCLUDE line: %s\n", buffer);
        continue;
      }

      dict = read_dictionary(dict, tmp_value_str);
      debugPrint("$INCLUDED %s\n", tmp_value_str);
    }
    else if (strncmp(buffer, "END-VENDOR", 10) == 0)
      vendorid = 0;
  }
  fclose(fp);
  free(tmp_id);
  free(tmp_type);
  free(tmp_name);
  free(tmp_value_str);
  free(buffer);

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


void free_attr(attr_entry *attr)
{
  if (attr == NULL)
    return;

  if (attr->next)
    free_attr(attr->next);

  free(attr->name);
  free(attr);
}

void free_vendor(vendor_entry *vendor)
{
  if (vendor == NULL)
    return;

  if (vendor->next)
    free_vendor(vendor->next);

  free(vendor->name);
  free(vendor);
}

void free_value(value_entry *value)
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
  free(dict);
  dict = NULL;
}

attr_entry *get_attr(dict_entry *dict, unsigned long long vendor, int id)
{
  attr_entry *attr = NULL;

  for (attr = dict->attr; attr != NULL; attr = attr->next)
    if (attr->vendor_id == vendor && attr->id == id)
      return attr;

  return NULL;
}

void print_attr_string_val(avp *attr)
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
    printf("Unknown Attribute\n");
    return;
  }

  printf("%s", dict_attr->name);
}

void print_index_val(dict_entry *dict, avp *attr)
{
  value_entry *value = NULL;
  guint32 id = 0, tmpint = 0;

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
    printf("Unknown Attribute\n");
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
    struct in_addr in;

    memcpy(&in.s_addr, attr->value, attr->len - 2);
    printf("%s", inet_ntoa(in));
  }
  else if (dict_attr->type == ATTR_TYPE_IPV6ADDR)
  {
    char *ip6addr = NULL;
    struct in6_addr in;

    if ((ip6addr = malloc(INET6_ADDRSTRLEN + 1)) == NULL)
      die("could not allocate memory for ip6addr\n");

    memset(ip6addr, 0, INET6_ADDRSTRLEN + 1);
    memcpy(&in.s6_addr, attr->value, attr->len - 2);

    if (inet_ntop(AF_INET6, &in, ip6addr, INET6_ADDRSTRLEN) == NULL)
      die("inet_ntop failed\n");

    printf("%s", ip6addr);
  }
  else
  {
    hexPrint(attr->value, attr->len - 2);
  }
}
