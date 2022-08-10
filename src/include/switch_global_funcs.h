#ifndef SWITCH_GLOBAL_FUNCS_H
#define SWITCH_GLOBAL_FUNCS_H

#include <switch.h>

typedef char* (*switch_get_outbound_proxy_fun)(const char* realm, const char* routeSet);
typedef char* (*switch_get_user_agent_fun)(const char* realm);
struct switch_global_functions
{
	switch_get_outbound_proxy_fun switch_get_outbound_proxy;
	switch_get_user_agent_fun switch_get_user_agent;
};

typedef struct switch_global_functions switch_global_functions;
SWITCH_DECLARE_DATA extern switch_global_functions SWITCH_GLOBAL_funcs;


#endif /* SWITCH_GLOBAL_FUNCS_H */
