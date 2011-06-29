#include <stdio.h>
#include <stdlib.h>

#include "radreplay.h"

static attr_entry *add_ignore(dict_entry *dict, attr_entry *old, const char *name)
{
  attr_entry *new = NULL, *tmp = NULL;

  debugPrint("Adding ignore record for attribute: %s\n", name);
  tmp = find_attribute_entry(dict, name);
  if (!tmp)
    return old;

  new = rrp_malloc(sizeof(attr_entry));

  if (old)
    new->next = old;
  else
    new->next = NULL;

  new->name = NULL;
  new->type = 0;
  new->id = tmp->id;
  new->vendor_id = tmp->vendor_id;

  return new;
}

void parse_ignore_string(dict_entry *dict, char *string)
{
  attr_entry *tmp_attr = NULL;
  char *c = string;

  while (*c != '\0')
  {
    if (*c == ':')
    {
      *c = '\0';
      tmp_attr = add_ignore(dict, tmp_attr, string);
      string = c;
      string++;
    }
    c++;
  }

  if (c != string)
    tmp_attr = add_ignore(dict, tmp_attr, string);

  dict->ignore = tmp_attr;
}

int is_ignored(attr_entry *ignore, avp *check)
{
  attr_entry *iter = NULL;

  for (iter = ignore; iter != NULL; iter = iter->next)
  {
    if (iter->id == check->code && iter->vendor_id == check->vendor)
      return 1;
  }

  return 0;
}
