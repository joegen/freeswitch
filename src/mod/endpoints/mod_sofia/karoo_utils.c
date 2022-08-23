#include "karoo_utils.h"

switch_bool_t glob_match(const char* wild, const char* string)
{
  const char *cp = NULL, *mp = NULL;
  while ((*string) && (*wild != '*')) {
    if ((*wild != *string) && (*wild != '?')) {
      return SWITCH_FALSE;
    }
    wild++;
    string++;
  }

  while (*string) {
    if (*wild == '*') {
      if (!*++wild) {
        return SWITCH_TRUE;
      }
      mp = wild;
      cp = string+1;
    } else if ((*wild == *string) || (*wild == '?')) {
      wild++;
      string++;
    } else {
      wild = mp;
      string = cp++;
    }
  }

  while (*wild == '*') {
    wild++;
  }
  return !*wild ? SWITCH_TRUE : SWITCH_FALSE;
}
