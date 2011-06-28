#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "rad-pcap-test.h"

extern char debug;

static void print_mismatch(char *mismatch, dict_entry *dict, avp *iter, avp *checkattr)
{
  printf("%s  Attribute Mismatch: ", *mismatch ? "" : "\n");
  *mismatch = 1;
  print_attr_name(dict, iter);
  printf(": ");
  print_attr_val(dict, iter);
  printf(" != ");
  print_attr_val(dict, checkattr);
  printf("\n");
}

/* Compare two lists of attribute value pairs. Returns 0 if they match, 1 if not */
int compare_avps(dict_entry *dict, avp *reference, avp *comparitor, char isRef)
{
  char mismatch = 0;
  avp *iter = NULL, *checkattr = NULL;

  for (iter = reference; iter != NULL; iter = iter->next)
  {
    checkattr = find_attribute(comparitor, iter->vendor, iter->code);
    if (!checkattr)
    {
      mismatch = 1;
      printf("%s  Attribute ", mismatch == 0 ? "\n" : "");
      print_attr_name(dict, iter);
      printf(" (");
      print_attr_val(dict, iter);
      printf(") is missing from the %s\n",
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
      print_mismatch(&mismatch, dict, iter, checkattr);
      continue;
    }

    /* check the value binary matches. if it does, move to the next one */
    if (memcmp(iter->value, checkattr->value, iter->len - 2) == 0)
      continue;

    print_mismatch(&mismatch, dict, iter, checkattr);
  }

  if (mismatch)
    return 1;

  return 0;
}


/* returns 0 on a match, 1 on a packet type mismatch, 2 on an attribute mismatch */
int check_payload (dict_entry *dict, packet_cache *reference, packet_cache *response)
{
  avp *refattr = NULL, *resattr = NULL, *userattr = NULL;
  char mismatch = 0;

  printf("Checking ");
  dump_pcache(reference, 0);

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

  /* find the username, this is helpful if we need to see why the attrs 
     don't match */
  if (!debug)
  {
    userattr = find_attribute(refattr, 0, 1);
    if (userattr)
    {
      printf(" Username: ");
      print_attr_val(dict, userattr);
    }
  }

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
