#ifndef SWITCH_GLOBAL_FUNCS_H
#define SWITCH_GLOBAL_FUNCS_H

#include <switch.h>


typedef char* (*switch_get_outbound_proxy_fun)(const char* user, const char* realm, const char* routeSet);
typedef char* (*switch_get_user_agent_fun)(const char* realm);
typedef char* (*switch_dialplan_fetch_fun)(const char *section, const char *tag_name, const char *key_name, const char *key_value, const char *paramsJson);
typedef int (*switch_is_user_existing_fun)(const char* user, const char* realm);
struct switch_global_functions
{
	switch_get_outbound_proxy_fun switch_get_outbound_proxy;
	switch_get_user_agent_fun switch_get_user_agent;
	switch_dialplan_fetch_fun switch_dialplan_fetch;
	switch_is_user_existing_fun switch_is_user_existing;
};

typedef struct switch_global_functions switch_global_functions;
SWITCH_DECLARE_DATA extern switch_global_functions SWITCH_GLOBAL_funcs;


#endif /* SWITCH_GLOBAL_FUNCS_H */
