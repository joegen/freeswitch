#include <switch_karoo_utils.h>


static KarooDialplanCallback karoo_dialplan_callback;

void switch_karoo_set_dialplan_callback(const KarooDialplanCallback& callback)
{
  karoo_dialplan_callback = callback;
}

bool switch_karoo_handle_dialplan_fetch(const char* section, const char* tag_name, const char* key_name, const char* key_value, switch_event_t* params, std::string& result)
{
  if (karoo_dialplan_callback)
  {
    return karoo_dialplan_callback(section, tag_name, key_name, key_value, params, result);
  }
  return false;
}
