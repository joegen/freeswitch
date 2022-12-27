#pragma once

#include <switch.h>
#include <functional>
#include <string>
#include <sstream>
#include <vector>

using KarooDialplanCallback = std::function<bool(const char* /*section*/, const char* /*tag_name*/, const char* /*key_name*/, const char* /*key_value*/, switch_event_t* /*params*/, std::string& /*result*/)>;

void switch_karoo_set_dialplan_callback(const KarooDialplanCallback& callback);
bool switch_karoo_handle_dialplan_fetch(const char* section, const char* tag_name, const char* key_name, const char* key_value, switch_event_t* params, std::string& result);
