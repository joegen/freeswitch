#ifndef KAROO_UTILS_H
#define KAROO_UTILS_H

#include <switch.h>

switch_bool_t karoo_glob_match(const char* wild, const char* str);
switch_bool_t karoo_profile_cmd(sofia_profile_t* profile, int argc, char** argv, switch_stream_handle_t *stream);
void karoo_del_gateway_glob(sofia_profile_t *profile, const char *glob);
void karoo_set_gateway_route(sofia_profile_t *profile, const char *gwname, const char *value);
void karoo_set_gateway_route_glob(sofia_profile_t *profile, const char *glob, const char *value);
void karoo_set_gateway_auth_username(sofia_profile_t *profile, const char *gwname, const char *value);
void karoo_set_gateway_auth_password(sofia_profile_t *profile, const char *gwname, const char *value);
void karoo_set_gateway_realm(sofia_profile_t *profile, const char *gwname, const char *value);
void karoo_set_gateway_from_user(sofia_profile_t *profile, const char *gwname, const char *value);
void karoo_set_gateway_from_domain(sofia_profile_t *profile, const char *gwname, const char *value);
void karoo_set_gateway_realm_and_from_domain(sofia_profile_t *profile, const char *gwname, const char *value);
void karoo_set_gateway_realm_and_from_domain_glob(sofia_profile_t *profile, const char *glob, const char *value);
void karoo_parse_single_gateway(sofia_profile_t *profile, switch_xml_t gateway);

#endif /* KAROO_UTILS_H */
