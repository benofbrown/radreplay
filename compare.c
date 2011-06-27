#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "rad-pcap-test.h"

extern char debug;

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

/* Compare two lists of attribute value pairs. Returns 0 if they match, 1 if not */
int compare_avps(dict_entry *dict, avp *reference, avp *comparitor, char isRef)
{
  int mismatch = 0;
  avp *iter = NULL, *checkattr = NULL;

  for (iter = reference; iter != NULL; iter = iter->next)
  {
    checkattr = find_attribute(comparitor, iter->vendor, iter->code);
    if (!checkattr)
    {
      mismatch = 1;
      printf("Attribute ");
      print_attr_name(dict, iter);
      printf(" (");
      print_attr_val(dict, iter);
      printf(") is in the %s but not the %s\n",
              isRef ? "reference" : "response",
              isRef ? "response" : "reference");

      continue;
    }

    /* if isRef == 0 then we're on the second pass, so mismatches have already
       been found */
    if (!isRef)
      continue;

    /* check they're the same length */
    if (iter->len != checkattr->len)
    {
      mismatch = 1;
      print_attr_name(dict, iter);
      printf(": ");
      print_attr_val(dict, iter);
      printf(" != ");
      print_attr_val(dict, checkattr);
      printf("\n");
      continue;
    }

    /* check the value binary matches. if it does, move to the next one */
    if (memcmp(iter->value, checkattr->value, iter->len - 2) == 0)
      continue;

    mismatch = 1;
    print_attr_name(dict, iter);
    printf(": ");
    print_attr_val(dict, iter);
    printf(" != ");
    print_attr_val(dict, checkattr);
    printf("\n");
  }

  if (mismatch)
    return 1;

  return 0;
}


/* returns 0 on a match, 1 on a near-match, 2 on a miss */
int check_payload (dict_entry *dict, packet_cache *reference, packet_cache *response)
{
  avp *refattr = NULL, *resattr = NULL;
  char mismatch = 0;

  /* check radius code, it's a small number so lowest overhead */
  if (reference->rad.code != response->rad.code)
    return 1;

  /* 
   * Check if there are any attributes. We know the codes match, so if the
   * lengths are both 0 there are no attrs and we have a match.
   */
  if (reference->attrlen == 0 && response->attrlen == 0)
      return 0;

  /* another simple one, do the attributes match? */
  if (reference->attrlen == response->attrlen
      && (memcmp(reference->attributes, response->attributes, response->attrlen) == 0))
    return 0;

  /* now it gets more complicated, we need to parse the attributes */
  refattr = parse_attributes(NULL, reference->attrlen, reference->attributes);
  debugPrint("Ref attrs:\n");
  if (debug && refattr)
    dump_attributes(dict, refattr);

  resattr = parse_attributes(NULL, response->attrlen, response->attributes);
  debugPrint("Res attrs:\n");
  if (debug && resattr)
    dump_attributes(dict, resattr);

  /* Now we loop through the reference attrs, and compare them with our response */
  mismatch = compare_avps(dict, refattr, resattr, 1);

  /* Now compare them the other way round */
  mismatch += compare_avps(dict, resattr, refattr, 0);

  /* free up the attributes */
  free_attributes(refattr);
  free_attributes(resattr);

  if (mismatch)
    return 2; 

  return 0;
}
