#include "mod_sofia.h"
#include "sofia-sip/sip_extra.h"
#include "karoo_utils.h"

switch_bool_t karoo_glob_match(const char* wild, const char* string)
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

void karoo_del_gateway_glob(sofia_profile_t *profile, const char *glob)
{
	sofia_gateway_t *gp = NULL;
	switch_mutex_lock(mod_sofia_globals.hash_mutex);
	for (gp = profile->gateways; gp; gp = gp->next) {
		if (karoo_glob_match(glob, gp->name)) {
			sofia_glue_del_gateway(gp);
		}
		sofia_glue_del_gateway(gp);
	}
	switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

switch_bool_t karoo_profile_cmd(sofia_profile_t* profile, int argc, char** argv, switch_stream_handle_t *stream)
{
  if (!strcasecmp(argv[1], "killgw_glob")) {
		karoo_del_gateway_glob(profile, argv[2]);
		stream->write_function(stream, "+OK glob %s marked for deletion.\n", argv[2]);
    return SWITCH_TRUE;
  }
  return SWITCH_FALSE;
}
