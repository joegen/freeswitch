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

void karoo_set_gateway_route_glob(sofia_profile_t *profile, const char *glob, const char *value)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (karoo_glob_match(glob, gp->name)) {
      gp->register_route = switch_core_strdup(gp->pool, value);
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

void karoo_set_gateway_realm(sofia_profile_t *profile, const char *gwname, const char *value)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (!strcasecmp(gwname, gp->name)) {
      gp->register_realm = switch_core_strdup(gp->pool, value);
      break;
    }
  }
  switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

void karoo_set_gateway_from_user(sofia_profile_t *profile, const char *gwname, const char *value)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (!strcasecmp(gwname, gp->name)) {
      gp->from_user = switch_core_strdup(gp->pool, value);
      break;
    }
  }
  switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

void karoo_set_gateway_from_domain(sofia_profile_t *profile, const char *gwname, const char *value)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (!strcasecmp(gwname, gp->name)) {
      gp->from_domain = switch_core_strdup(gp->pool, value);
      gp->register_realm = switch_core_strdup(gp->pool, value);
      break;
    }
  }
  switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

void karoo_set_gateway_realm_and_from_domain(sofia_profile_t *profile, const char *gwname, const char *value)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (!strcasecmp(gwname, gp->name)) {
      gp->from_domain = switch_core_strdup(gp->pool, value);
      break;
    }
  }
  switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

void karoo_set_gateway_realm_and_from_domain_glob(sofia_profile_t *profile, const char *glob, const char *value)
{
  sofia_gateway_t *gp = NULL;
  switch_mutex_lock(mod_sofia_globals.hash_mutex);
  for (gp = profile->gateways; gp; gp = gp->next) {
    if (karoo_glob_match(glob, gp->name)) {
      gp->from_domain = switch_core_strdup(gp->pool, value);
      gp->register_realm = switch_core_strdup(gp->pool, value);
    }
  }
  switch_mutex_unlock(mod_sofia_globals.hash_mutex);
}

void karoo_parse_single_gateway(sofia_profile_t *profile, switch_xml_t gateway_tag)
{
  switch_xml_t param = NULL, x_params;
	sofia_gateway_t *gp;
	switch_memory_pool_t *pool;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
  char *name = (char *) switch_xml_attr_soft(gateway_tag, "name");
	sofia_gateway_t *gateway;
	char *pkey = switch_mprintf("%s::%s", profile->name, name);

	if (zstr(name) || switch_regex_match(name, "^[\\w\\.\\-\\_]+$") != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Ignoring invalid name '%s'\n", name ? name : "NULL");
		free(pkey);
		return;
	}

	switch_mutex_lock(mod_sofia_globals.hash_mutex);
	if ((gp = switch_core_hash_find(mod_sofia_globals.gateway_hash, name)) && (gp = switch_core_hash_find(mod_sofia_globals.gateway_hash, pkey)) && !gp->deleted) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Ignoring duplicate gateway '%s'\n", name);
		switch_mutex_unlock(mod_sofia_globals.hash_mutex);
		free(pkey);
		return;
	}
	free(pkey);
	switch_mutex_unlock(mod_sofia_globals.hash_mutex);

	if ((status = switch_core_new_memory_pool(&pool)) != SWITCH_STATUS_SUCCESS) {
		return;
	}

	if ((gateway = switch_core_alloc(pool, sizeof(*gateway)))) {
		const char *sipip, *format;
		int sipport = 5060;
		int force_sipport = 0;
		switch_uuid_t uuid;
		uint32_t ping_freq = 0, use_standard_contact = 0, extension_in_contact = 0, contact_in_ping = 0, ping_monitoring = 0, distinct_to = 0, rfc_5626 = 0;
		int ping_max = 1, ping_min = 1;
		char *register_str = "true", *scheme = "Digest",
			*realm = NULL,
			*username = NULL,
			*auth_username = NULL,
			*password = NULL,
			*caller_id_in_from = "false",
			*extension = NULL,
			*proxy = NULL,
			*options_user_agent = NULL,
			*context = profile->context,
			*expire_seconds = "3600",
			*retry_seconds = "30",
			*max_retry_seconds = "600",
			*fail_908_retry_seconds = NULL,
			*timeout_seconds = "60",
			*from_user = "", *from_domain = NULL, *outbound_proxy = NULL, *register_proxy = NULL, *contact_host = NULL,
			*contact_params = "", *params = NULL, *register_transport = NULL,
			*reg_id = NULL, *str_rfc_5626 = "";

		if (!context) {
			context = "default";
		}

		switch_uuid_get(&uuid);
		switch_uuid_format(gateway->uuid_str, &uuid);

		gateway->register_transport = SOFIA_TRANSPORT_UDP;
		gateway->pool = pool;
		gateway->profile = profile;
		gateway->name = switch_core_strdup(gateway->pool, name);
		gateway->freq = 0;
		gateway->next = NULL;
		gateway->ping = 0;
		gateway->ping_freq = 0;
		gateway->ping_max = 0;
		gateway->ping_min = 0;
		gateway->ping_sent = 0;
		gateway->ping_time = 0;
		gateway->ping_count = 0;
		gateway->ping_monitoring = SWITCH_FALSE;
		gateway->ib_calls = 0;
		gateway->ob_calls = 0;
		gateway->ib_failed_calls = 0;
		gateway->ob_failed_calls = 0;
		gateway->destination_prefix = "";
		gateway->registration_spread = 5;
		gateway->deleted = 0;

		if ((x_params = switch_xml_child(gateway_tag, "variables"))) {
			param = switch_xml_child(x_params, "variable");
		} else {
			param = switch_xml_child(gateway_tag, "variable");
		}


		for (; param; param = param->next) {
			const char *var = switch_xml_attr(param, "name");
			const char *val = switch_xml_attr(param, "value");
			const char *direction = switch_xml_attr(param, "direction");
			int in = 0, out = 0;

			if (var && val) {
				if (direction) {
					if (!strcasecmp(direction, "inbound")) {
						in = 1;
					} else if (!strcasecmp(direction, "outbound")) {
						out = 1;
					}
				} else {
					in = out = 1;
				}

				if (in) {
					if (!gateway->ib_vars) {
						switch_event_create_plain(&gateway->ib_vars, SWITCH_EVENT_GENERAL);
					}
					switch_event_add_header_string(gateway->ib_vars, SWITCH_STACK_BOTTOM, var, val);
				}

				if (out) {
					if (!gateway->ob_vars) {
						switch_event_create_plain(&gateway->ob_vars, SWITCH_EVENT_GENERAL);
					}
					switch_event_add_header_string(gateway->ob_vars, SWITCH_STACK_BOTTOM, var, val);
				}
			}
		}

		if ((x_params = switch_xml_child(gateway_tag, "params"))) {
			param = switch_xml_child(x_params, "param");
		} else {
			param = switch_xml_child(gateway_tag, "param");
		}

		for (; param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");

			if (!strcmp(var, "register")) {
				register_str = val;
			} else if (!strcmp(var, "scheme")) {
				scheme = val;
			} else if (!strcmp(var, "realm")) {
				realm = val;
			} else if (!strcmp(var, "username")) {
				username = val;
			} else if (!strcmp(var, "extension-in-contact")) {
				extension_in_contact = switch_true(val);
			} else if (!strcmp(var, "use-standard-contact")) {
				use_standard_contact = switch_true(val);
			} else if (!strcmp(var, "auth-username")) {
				auth_username = val;
			} else if (!strcmp(var, "password")) {
				password = val;
			} else if (!strcmp(var, "caller-id-in-from")) {
				caller_id_in_from = val;
			} else if (!strcmp(var, "extension")) {
				extension = val;
			} else if (!strcmp(var, "contact-in-ping")) {
				contact_in_ping = switch_true(val);
			} else if (!strcmp(var, "ping")) {
				ping_freq = atoi(val);
			} else if (!strcmp(var, "registration-spread")) {
				gateway->registration_spread = atoi(val);
			} else if (!strcmp(var, "force-sipport")) {
				force_sipport = atoi(val);
			} else if (!strcmp(var, "ping-max")) {
				ping_max = atoi(val);
			} else if (!strcmp(var, "ping-min")) {
				ping_min = atoi(val);
			} else if (!strcmp(var, "ping-user-agent")) {
				options_user_agent = val;
			} else if (!strcmp(var, "ping-monitoring")) { // if true then every gw ping result will fire a gateway status event
				ping_monitoring = switch_true(val);
			} else if (!strcmp(var, "proxy")) {
				proxy = val;
			} else if (!strcmp(var, "context")) {
				context = val;
			} else if (!strcmp(var, "expire-seconds")) {
				expire_seconds = val;
			} else if (!strcmp(var, "908-retry-seconds")) {
				fail_908_retry_seconds = val;
			} else if (!strcmp(var, "retry-seconds")) {
				retry_seconds = val;
			} else if (!strcmp(var, "max-retry-seconds")) {
				max_retry_seconds = val;
			} else if (!strcmp(var, "timeout-seconds")) {
				timeout_seconds = val;
			} else if (!strcmp(var, "retry_seconds")) {	// support typo for back compat
				retry_seconds = val;
			} else if (!strcmp(var, "from-user")) {
				from_user = val;
			} else if (!strcmp(var, "from-domain")) {
				from_domain = val;
			} else if (!strcmp(var, "contact-host")) {
				contact_host = val;
			} else if (!strcmp(var, "register-proxy")) {
				register_proxy = val;
				gateway->register_proxy_host_cfg = sofia_glue_get_host_from_cfg(register_proxy, gateway->pool);
			} else if (!strcmp(var, "register-route")) {
				if (!zstr(val)) {
					gateway->register_route = switch_core_strdup(gateway->pool, val);
				} 
			} else if (!strcmp(var, "outbound-proxy")) {
				outbound_proxy = val;
				gateway->outbound_proxy_host_cfg = sofia_glue_get_host_from_cfg(outbound_proxy, gateway->pool); 
			} else if (!strcmp(var, "distinct-to")) {
				distinct_to = switch_true(val);
			} else if (!strcmp(var, "destination-prefix")) {
				if (!zstr(val)) {
					gateway->destination_prefix = switch_core_strdup(gateway->pool, val);
				}
			} else if (!strcmp(var, "rfc-5626")) {
				rfc_5626 = switch_true(val);
			} else if (!strcmp(var, "reg-id")) {
				reg_id = val;
			} else if (!strcmp(var, "contact-params")) {
				contact_params = val;
			} else if (!strcmp(var, "register-transport")) {
				sofia_transport_t transport = sofia_glue_str2transport(val);

				if (transport == SOFIA_TRANSPORT_UNKNOWN || (!sofia_test_pflag(profile, PFLAG_TLS) && sofia_glue_transport_has_tls(transport))) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ERROR: unsupported transport\n");
					return;
				}

				gateway->register_transport = transport;
			} else if (!strcmp(var, "gw-auth-acl")) {
				if (!zstr(val)) {
					gateway->gw_auth_acl = switch_core_strdup(gateway->pool, val);
				}
			}
		}

		/* RFC 5626 enable in the GW profile and the UA profile */
		if (rfc_5626 && sofia_test_pflag(profile, PFLAG_ENABLE_RFC5626)) {
			char str_guid[su_guid_strlen + 1];
			su_guid_t guid[1];
			su_guid_generate(guid);
			su_guid_sprintf(str_guid, su_guid_strlen + 1, guid);
			str_rfc_5626 = switch_core_sprintf(gateway->pool, ";reg-id=%s;+sip.instance=\"<urn:uuid:%s>\"",reg_id,str_guid);
		}

		if (zstr(realm)) {
			if (zstr(proxy)) {
				realm = name;
			} else {
				realm = proxy;
			}
		}

		if (switch_true(register_str)) {
			if (zstr(username)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ERROR: username param is REQUIRED!\n");
				return;
			}

			if (zstr(password)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ERROR: password param is REQUIRED!\n");
				return;
			}
		} else {
			if (zstr(username)) {
				username = "FreeSWITCH";
			}

			if (zstr(password)) {
				password = "";
			}
		}

		if (zstr(from_user)) {
			from_user = username;
		}

		if (zstr(proxy)) {
			proxy = realm;
		}

		gateway->proxy_host_cfg = sofia_glue_get_host_from_cfg(proxy, gateway->pool);

		if (!switch_true(register_str)) {
			gateway->state = REG_STATE_NOREG;
			gateway->status = SOFIA_GATEWAY_UP;
			gateway->uptime = switch_time_now();
		}
		else
		{
		  gateway->state = REG_STATE_UNREGED;;
			gateway->status = SOFIA_GATEWAY_DOWN;
		}

		if (zstr(auth_username)) {
			auth_username = username;
		}

		if (!zstr(register_proxy)) {
			if (strncasecmp(register_proxy, "sip:", 4) && strncasecmp(register_proxy, "sips:", 5)) {
				gateway->register_sticky_proxy = switch_core_sprintf(gateway->pool, "sip:%s", register_proxy);
			} else {
				gateway->register_sticky_proxy = switch_core_strdup(gateway->pool, register_proxy);
			}
		}

		if (!zstr(outbound_proxy)) {
			if (strncasecmp(outbound_proxy, "sip:", 4) && strncasecmp(outbound_proxy, "sips:", 5)) {
				gateway->outbound_sticky_proxy = switch_core_sprintf(gateway->pool, "sip:%s", outbound_proxy);
			} else {
				gateway->outbound_sticky_proxy = switch_core_strdup(gateway->pool, outbound_proxy);
			}
		}

		gateway->retry_seconds = atoi(retry_seconds);
		gateway->max_retry_seconds = atoi(max_retry_seconds);

		if (fail_908_retry_seconds) {
			gateway->fail_908_retry_seconds = atoi(fail_908_retry_seconds);
		}

		if (gateway->retry_seconds < 5) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Invalid retry-seconds of %d on gateway %s, using the value of 30 instead.\n",
								gateway->retry_seconds, name);
			gateway->retry_seconds = 30;
		}

		gateway->reg_timeout_seconds = atoi(timeout_seconds);

		if (gateway->reg_timeout_seconds < 5) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Invalid timeout-seconds of %d on gateway %s, using the value of 60 instead.\n",
								gateway->reg_timeout_seconds, name);
			gateway->reg_timeout_seconds = 60;
		}

		gateway->register_scheme = switch_core_strdup(gateway->pool, scheme);
		gateway->register_context = switch_core_strdup(gateway->pool, context);
		gateway->register_realm = switch_core_strdup(gateway->pool, realm);
		gateway->register_username = switch_core_strdup(gateway->pool, username);
		gateway->auth_username = switch_core_strdup(gateway->pool, auth_username);
		gateway->register_password = switch_core_strdup(gateway->pool, password);
		gateway->distinct_to = distinct_to;
		gateway->options_user_agent = options_user_agent;

		if (switch_true(caller_id_in_from)) {
			sofia_set_flag(gateway, REG_FLAG_CALLERID);
		}

		register_transport = (char *) sofia_glue_transport2str(gateway->register_transport);

		if (! zstr(contact_params)) {
			if (*contact_params == ';') {
				if (use_standard_contact) {
					params = switch_core_sprintf(gateway->pool, "%s;transport=%s", contact_params, register_transport);
				} else {
					params = switch_core_sprintf(gateway->pool, "%s;transport=%s;gw=%s", contact_params, register_transport, gateway->name);
				}
			} else {
				if (use_standard_contact) {
					params = switch_core_sprintf(gateway->pool, ";%s;transport=%s", contact_params, register_transport);
				} else {
					params = switch_core_sprintf(gateway->pool, ";%s;transport=%s;gw=%s", contact_params, register_transport, gateway->name);
				}
			}
		} else {
			if (use_standard_contact) {
					params = switch_core_sprintf(gateway->pool, ";transport=%s", register_transport);
			} else {
				params = switch_core_sprintf(gateway->pool, ";transport=%s;gw=%s", register_transport, gateway->name);
			}
		}

		if (!zstr(from_domain)) {
			gateway->from_domain = switch_core_strdup(gateway->pool, from_domain);
		}

#if 0
		if (!zstr(register_transport) && !switch_stristr("transport=", proxy)) {
			gateway->register_url = switch_core_sprintf(gateway->pool, "sip:%s;transport=%s", proxy, register_transport);
		} else {
			gateway->register_url = switch_core_sprintf(gateway->pool, "sip:%s", proxy);
		}
#else
		gateway->register_url = switch_core_sprintf(gateway->pool, "sip:%s", !zstr(from_domain) ? from_domain : proxy);
#endif

		gateway->register_from = switch_core_sprintf(gateway->pool, "<sip:%s@%s>",
				from_user, !zstr(from_domain) ? from_domain : proxy);
		gateway->from_user = switch_core_strdup(gateway->pool, from_user);
		if (ping_freq) {
			if (ping_freq >= 5) {
				gateway->ping_freq = ping_freq;
				gateway->ping_max = ping_max;
				gateway->ping_min = ping_min;
				gateway->ping_monitoring = ping_monitoring;
				gateway->ping = switch_epoch_time_now(NULL) + ping_freq;
				gateway->options_to_uri = switch_core_sprintf(gateway->pool, "<sip:%s>",
					!zstr(from_domain) ? from_domain : proxy);
				gateway->options_from_uri = gateway->options_to_uri;
				if (contact_in_ping) {
					gateway->contact_in_ping = contact_in_ping;
				}	
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ERROR: invalid ping!\n");
			}
		}

		if (contact_host) {
			if (!strcmp(contact_host, "sip-ip")) {
				sipip = profile->sipip;
			} else {
				sipip = contact_host;
			}
		} else if (profile->extsipip) {
			sipip = profile->extsipip;
		} else {
			sipip = profile->sipip;
		}

		if (zstr(extension)) {
			extension = username;
		} else {
			gateway->real_extension = switch_core_strdup(gateway->pool, extension);
		}

		gateway->extension = switch_core_strdup(gateway->pool, extension);

		if (!strncasecmp(proxy, "sip:", 4)) {
			gateway->register_proxy = switch_core_strdup(gateway->pool, proxy);
			gateway->register_to = switch_core_sprintf(gateway->pool, "sip:%s@%s", username, proxy + 4);
		} else {
			gateway->register_proxy = switch_core_sprintf(gateway->pool, "sip:%s", proxy);
			gateway->register_to = switch_core_sprintf(gateway->pool, "sip:%s@%s", username, proxy);
		}

		/* This checks to make sure we provide the right contact on register for targets behind nat with us. */
		if (sofia_test_pflag(profile, PFLAG_AUTO_NAT)) {
			char *register_host = NULL;

			register_host = sofia_glue_get_register_host(gateway->register_proxy);

			if (register_host && switch_is_lan_addr(register_host)) {
				sipip = profile->sipip;
			}

			switch_safe_free(register_host);
		}

		if (force_sipport) {
			sipport = force_sipport;
		} else {
			sipport = sofia_glue_transport_has_tls(gateway->register_transport) ?
						profile->tls_sip_port : profile->extsipport;
		}

		if (use_standard_contact)
		{
			format = strchr(sipip, ':') ? "<sip:%s@[%s]:%d%s>" : "<sip:%s@%s:%d%s>";
				gateway->register_contact = switch_core_sprintf(gateway->pool, format, from_user,
						sipip,
						sipport, params);
		} else if (extension_in_contact) {
			if (rfc_5626) {
				format = strchr(sipip, ':') ? "<sip:%s@[%s]:%d>%s" : "<sip:%s@%s:%d%s>%s";
				gateway->register_contact = switch_core_sprintf(gateway->pool, format, extension,
						sipip,
						sipport, params, str_rfc_5626);

			} else {
				format = strchr(sipip, ':') ? "<sip:%s@[%s]:%d%s>" : "<sip:%s@%s:%d%s>";
				gateway->register_contact = switch_core_sprintf(gateway->pool, format, extension,
						sipip,
						sipport, params);
			}
		} else {
			if (rfc_5626) {
				format = strchr(sipip, ':') ? "<sip:gw+%s@[%s]:%d%s>%s" : "<sip:gw+%s@%s:%d%s>%s";
				gateway->register_contact = switch_core_sprintf(gateway->pool, format, gateway->name,
						sipip,
						sipport, params, str_rfc_5626);

			} else {
				format = strchr(sipip, ':') ? "<sip:gw+%s@[%s]:%d%s>" : "<sip:gw+%s@%s:%d%s>";
				gateway->register_contact = switch_core_sprintf(gateway->pool, format, gateway->name,
						sipip,
						sipport, params);

			}
		}

		gateway->expires_str = switch_core_strdup(gateway->pool, expire_seconds);

		if ((gateway->freq = atoi(gateway->expires_str)) < 5) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
								"Invalid register-frequency of %d on gateway %s, using the value of 3600 instead\n", gateway->freq, name);
			gateway->freq = 3600;
		}

		sofia_reg_add_gateway(profile, gateway->name, gateway);
		sofia_reg_check_gateway(profile, switch_epoch_time_now(NULL));

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,"Added new gateway %s [%p]\n",  gateway->name, (void*)gateway);
	}
}

static switch_xml_t karoo_create_xml_from_args(int argc, char** argv)
{
	switch_stream_handle_t stream = { 0 };
	switch_xml_t xml = NULL;
  SWITCH_STANDARD_STREAM(stream);
	if (argc > 3) {
		for (int i = 2; i < argc; i++) {
			stream.write_function(&stream, "%s ", argv[i]);
		}
	}
	xml = switch_xml_parse_str_dup(stream.data);
	switch_safe_free(stream.data);
	return xml;
}

switch_bool_t karoo_profile_cmd(sofia_profile_t* profile, int argc, char** argv, switch_stream_handle_t *stream)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Checking if argv[1] %s is a karoo command\n", argv[1]);
  if (argc == 3 && !strcasecmp(argv[1], "killgw_glob")) {
		karoo_del_gateway_glob(profile, argv[2]);
		stream->write_function(stream, "+OK glob %s marked for deletion.\n", argv[2]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_route")) {
		karoo_set_gateway_route(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK route %s set for gateway %s.\n", argv[2], argv[3]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_route_glob")) {
		karoo_set_gateway_route_glob(profile, argv[2], argv[3]);
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
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_from_user")) {
		karoo_set_gateway_from_user(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK from-user set for gateway %s.\n", argv[3]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_from_domain")) {
		karoo_set_gateway_from_domain(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK from-domain set for gateway %s.\n", argv[3]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_realm")) {
		karoo_set_gateway_realm(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK realm set for gateway %s.\n", argv[3]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_realm_and_domain")) {
		karoo_set_gateway_realm_and_from_domain(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK realm/domain set for gateway %s.\n", argv[3]);
    return SWITCH_TRUE;
  } else if (argc == 4 && !strcasecmp(argv[1], "setgw_realm_and_domain_glob")) {
		karoo_set_gateway_realm_and_from_domain_glob(profile, argv[2], argv[3]);
		stream->write_function(stream, "+OK realm/domain set for gateway %s.\n", argv[3]);
    return SWITCH_TRUE;
  } else if (argc >= 4 && !strcasecmp(argv[1], "addgw")) {
		switch_xml_t xml = karoo_create_xml_from_args(argc, argv);
		if (xml) {
			karoo_parse_single_gateway(profile, xml);
			stream->write_function(stream, "+OK gateway added.\n");
		} else {
			stream->write_function(stream, "-ERR gateway not added.\n");
		}
		return SWITCH_TRUE;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "argv[1] %s is a not karoo command\n", argv[1]);
  return SWITCH_FALSE;
}
