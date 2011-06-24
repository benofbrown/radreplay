#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rad-pcap-test.h"

dict_entry *read_dictionary(dict_entry *old, const char *file)
{
  FILE *fp = NULL;
  char *buffer = NULL;
  size_t buflen = 128;
  int vendorid = 0;
  attr_entry *tmp_attr = NULL;
  vendor_entry *tmp_vendor = NULL;
  char *tmpchar = NULL, *tmp_id = NULL, *tmp_type = NULL, *tmp_name = NULL;
  dict_entry *dict = NULL;

  if (old)
    dict = old;
  else
  {
    if ((dict = malloc(sizeof(dict_entry))) == NULL)
      die("Could not allocate dict\n");

    dict->attr = NULL;
    dict->vendor = NULL;
  }

  if ((buffer = malloc(buflen + 1)) == NULL)
    die("Could not allocate buffer\n");

  if ((tmp_id = malloc(9)) == NULL)
    die("Could not allocate tmp_id\n");

  if ((tmp_type = malloc(17)) == NULL)
    die("Could not allocate tmp_type\n");

  if ((tmp_name = malloc(33)) == NULL)
    die("Could not allocate tmp_name\n");

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
      tmp_attr->id = strtod(tmp_id, NULL);
      tmp_attr->vendor_id = vendorid;
      strncpy(tmp_attr->name, tmp_name, 32);

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
      strncpy(tmp_vendor->name, tmp_name, 32);
      tmp_vendor->id = strtod(tmp_id, NULL);
      vendorid = tmp_vendor->id;

      debugPrint("Vendor %s id: %d\n", tmp_vendor->name, tmp_vendor->id);

      if (dict->vendor)
        tmp_vendor->next = dict->vendor;

      dict->vendor = tmp_vendor;
    }
    else if (strncmp(buffer, "END-VENDOR", 10) == 0)
      vendorid = 0;
  }
  fclose(fp);
  free(tmp_id);
  free(tmp_type);
  free(tmp_name);
  free(buffer);

  return dict;
}

void free_attr(attr_entry *attr)
{
  if (attr == NULL)
    return;

  if (attr->next)
    free_attr(attr->next);

  free(attr);
}

void free_vendor(vendor_entry *vendor)
{
  if (vendor == NULL)
    return;

  if (vendor->next)
    free_vendor(vendor->next);

  free(vendor);
}

void free_dictionary(dict_entry *dict)
{
  if (dict == NULL)
    return;

  free_attr(dict->attr);
  free_vendor(dict->vendor);
  free(dict);
  dict = NULL;
}
