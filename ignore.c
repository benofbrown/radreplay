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

#include "radreplay.h"

static attr_entry *add_ignore(dict_entry *dict, attr_entry *old, const char *name)
{
  attr_entry *new = NULL, *tmp = NULL;

  tmp = find_attribute_entry(dict, name);
  if (!tmp)
    return old;

  printf("INFO: ignoring differences in attribute: %s\n", name);

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
