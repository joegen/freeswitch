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

void karoo_set_gateway_route(sofia_profile_t *profile, const char *gwname, const char *route)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (!strcasecmp(gwname, gp->name)) {
      gp->register_route = switch_core_strdup(gp->pool, route);
      break;
    }
  }
  switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

void karoo_set_gateway_auth_username(sofia_profile_t *profile, const char *gwname, const char *user)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (!strcasecmp(gwname, gp->name)) {
      gp->auth_username = switch_core_strdup(gp->pool, user);
      break;
    }
  }
  switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

void karoo_set_gateway_auth_password(sofia_profile_t *profile, const char *gwname, const char *password)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (!strcasecmp(gwname, gp->name)) {
      gp->register_password = switch_core_strdup(gp->pool, password);
      break;
    }
  }
  switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

switch_bool_t karoo_profile_cmd(sofia_profile_t* profile, int argc, char** argv, switch_stream_handle_t *stream)
{
  if (argc == 3 && !strcasecmp(argv[1], "killgw_glob")) {
		karoo_del_gateway_glob(profile, argv[2]);
		stream->write_function(stream, "+OK glob %s marked for deletion.\n", argv[2]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_route")) {
		karoo_set_gateway_route(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK route %s set for gateway %s.\n", argv[2], argv[3]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_user")) {
		karoo_set_gateway_auth_username(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK user %s set for gateway %s.\n", argv[2], argv[3]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_password")) {
		karoo_set_gateway_auth_password(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK password set for gateway %s.\n", argv[3]);
    return SWITCH_TRUE;
  }
  return SWITCH_FALSE;
}
