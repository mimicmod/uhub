/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2013, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "plugin_api/handle.h"
#include "util/memory.h"
#include "util/config_token.h"

enum Warnings
{
	WARN_SEARCH         = 0x01, ///<<< "Warn about searching."
	WARN_CONNECT        = 0x02, ///<<< "Warn about connecting to a user"
	WARN_REVCONNECT     = 0x04, ///<<< "Used for passive user allowed to connect to other user"
	WARN_CHAT           = 0x08, ///<<< "Warn about chat disallowed."
	WARN_PM             = 0x10, ///<<< "Warn about private chat disallowed."
	WARN_OP_PM          = 0x20, ///<<< "Warn about op contact disallowed."
	WARN_OP_REVPM       = 0x40, ///<<< "Used for user already contacted by op."
};

struct user_info
{
	sid_t sid;      // The SID of the user
	int warnings;   // The number of denies (used to track wether or not a warning should be sent). @see enum Warnings.
};

struct restrict_data
{
	size_t num_users;        // number of users tracked.
	size_t max_users;        // max users (hard limit max 1M users due to limitations in the SID (20 bits)).
	struct user_info* users; // array of max_users
	enum auth_credentials min_cred_use_hub;   // minimum credentials to override search and download limitations.
	enum auth_credentials min_cred_pm;   // minimum credentials to allow using private chat
	enum auth_credentials min_cred_pm_op; // minimum credentials to allow private chat to operators (including super and admins).
	enum auth_credentials min_cred_mainchat;   // minimum credentials to allow using main chat
};

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

static struct restrict_data* co_initialize(const char* line, struct plugin_handle* plugin)
{
	struct restrict_data* data = (struct restrict_data*) hub_malloc(sizeof(struct restrict_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
		return 0;

	// defaults
	data->num_users = 0;
	data->max_users = 512;
	data->users = hub_malloc_zero(sizeof(struct user_info) * data->max_users);
	data->min_cred_use_hub = auth_cred_user;
	data->min_cred_pm = auth_cred_user;
	data->min_cred_pm_op = auth_cred_user;
	data->min_cred_mainchat = auth_cred_user;

	while (token)
	{
		struct cfg_settings* setting = cfg_settings_split(token);

		if (!setting)
		{
			set_error_message(plugin, "Unable to parse startup parameters");
			cfg_tokens_free(tokens);
			hub_free(data);
			return 0;
		}

		if (strcmp(cfg_settings_get_key(setting), "min_cred_use_hub") == 0)
		{
			auth_string_to_cred(cfg_settings_get_value(setting), &data->min_cred_use_hub);
		}
		else if (strcmp(cfg_settings_get_key(setting), "min_cred_pm") == 0)
		{
			auth_string_to_cred(cfg_settings_get_value(setting), &data->min_cred_pm);
		}
		else if (strcmp(cfg_settings_get_key(setting), "min_cred_pm_op") == 0)
		{
			auth_string_to_cred(cfg_settings_get_value(setting), &data->min_cred_pm_op);
		}
		else if (strcmp(cfg_settings_get_key(setting), "min_cred_mainchat") == 0)
		{
			auth_string_to_cred(cfg_settings_get_value(setting), &data->min_cred_mainchat);
		}
		else
		{
			set_error_message(plugin, "Unknown startup parameters given");
			cfg_tokens_free(tokens);
			cfg_settings_free(setting);
			hub_free(data);
			return 0;
		}

		cfg_settings_free(setting);
		token = cfg_token_get_next(tokens);
	}

	cfg_tokens_free(tokens);
	return data;
}

static void co_shutdown(struct restrict_data* data)
{
	if (data)
	{
		hub_free(data->users);
		hub_free(data);
	}
}

static struct user_info* get_user_info(struct restrict_data* data, sid_t sid)
{
	struct user_info* u;

	// resize buffer if needed.
	if (sid >= data->max_users)
	{
		u = hub_malloc_zero(sizeof(struct user_info) * (sid + 1));
		memcpy(u, data->users, data->max_users);
		hub_free(data->users);
		data->users = u;
		data->max_users = sid + 1;
		u = NULL;
	}

	u = &data->users[sid];

	// reset counters if the user was not previously known.
	if (!u->sid)
	{
		u->sid = sid;
		u->warnings = 0;
		data->num_users++;
	}
	return u;
}

static plugin_st on_search_result(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* search_data)
{
	struct restrict_data* data = (struct restrict_data*) plugin->ptr;

	if (to->credentials >= data->min_cred_use_hub)
		return st_allow;

	return st_deny;
}

static plugin_st on_search(struct plugin_handle* plugin, struct plugin_user* user, const char* search_data)
{
	struct restrict_data* data = (struct restrict_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, user->sid);

	if (user->credentials >= data->min_cred_use_hub)
		return st_allow;

	if (!(info->warnings & WARN_SEARCH))
	{
		plugin->hub.send_status_message(plugin, user, 000, "You are not allowed to search on this hub.");
		info->warnings |= WARN_SEARCH;
	}
	return st_deny;
}

static plugin_st on_p2p_connect(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to)
{
	struct restrict_data* data = (struct restrict_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, from->sid);
	struct user_info* target = get_user_info(data, to->sid);

	if (from->credentials >= data->min_cred_use_hub || (target->warnings & WARN_REVCONNECT))
		return st_allow;

	if (!(info->warnings & WARN_CONNECT))
	{
		plugin->hub.send_status_message(plugin, from, 000, "You are not allowed to setup connection to other users on this hub.");
		info->warnings |= WARN_CONNECT;
	}
	return st_deny;
}

static plugin_st on_p2p_revconnect(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to)
{
	struct restrict_data* data = (struct restrict_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, from->sid);

	if (from->credentials >= data->min_cred_use_hub)
	{
		info->warnings |= WARN_REVCONNECT;
		return st_allow;
	}

	if (!(info->warnings & WARN_CONNECT))
	{
		plugin->hub.send_status_message(plugin, from, 000, "You are not allowed to setup connection to other users on this hub.");
		info->warnings |= WARN_CONNECT;
	}
	return st_deny;
}

plugin_st on_chat_msg(struct plugin_handle* plugin, struct plugin_user* from, const char* message)
{
	struct restrict_data* data = (struct restrict_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, from->sid);

	if (from->credentials < data->min_cred_mainchat)
	{
		if (!(info->warnings & WARN_CHAT))
		{
			plugin->hub.send_status_message(plugin, from, 000, "You are not allowed to send public messages on this hub.");
			info->warnings |= WARN_CHAT;
		}
		return st_deny;
	}
	return st_default;
}

plugin_st on_private_msg(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* message)
{
	struct restrict_data* data = (struct restrict_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, from->sid);
	struct user_info* target = get_user_info(data, to->sid);
	
	if (from->credentials >= data->min_cred_pm && from->credentials >= auth_cred_operator && to->credentials < auth_cred_operator)
	{
		target->warnings |= WARN_OP_REVPM; // user is contacted by an op first, lets mark him as allowed to answer;
		return st_allow;
	}

	if (to->credentials >= auth_cred_operator) // recipient is op
	{
		if (from->credentials >= data->min_cred_pm_op) // sender is allowed to contact ops
			return st_allow;

		if (!(info->warnings & WARN_OP_REVPM)) // sender is not marked as contacted by op in the past
		{
			if (!(info->warnings & WARN_OP_PM))
			{
				plugin->hub.send_status_message(plugin, from, 000, "You are not allowed to send private messages to operators on this hub.");
				info->warnings |= WARN_OP_PM;
			}
			return st_deny;
		}
	}

	if (from->credentials < data->min_cred_pm && to->credentials < auth_cred_operator) // user is not allowed to send an ordinary PM (recipient is not op)
	{
		if (!(info->warnings & WARN_PM))
		{
			plugin->hub.send_status_message(plugin, from, 000, "You are not allowed to send private messages on this hub.");
			info->warnings |= WARN_PM;
		}
		return st_deny;
	}

	return st_default;
}

static void on_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct restrict_data* data = (struct restrict_data*) plugin->ptr;
	/*struct user_info* info = */
	get_user_info(data, user->sid);
}

static void on_user_logout(struct plugin_handle* plugin, struct plugin_user* user, const char* reason)
{
	struct restrict_data* data = (struct restrict_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, user->sid);
	if (info->sid)
		data->num_users--;
	info->warnings = 0;
	info->sid = 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct restrict_data* data;
	PLUGIN_INITIALIZE(plugin, "Restricted hub", "1.0", "Disables connection setup, search and results, chat, private messages under given credentials.");
	data = co_initialize(config, plugin);

	if (!data)
		return -1;

	plugin->funcs.on_search = on_search;
	plugin->funcs.on_search_result = on_search_result;
	plugin->funcs.on_p2p_connect = on_p2p_connect;
	plugin->funcs.on_p2p_revconnect = on_p2p_revconnect;
	plugin->funcs.on_chat_msg = on_chat_msg;
	plugin->funcs.on_private_msg = on_private_msg;
	plugin->funcs.on_user_login = on_user_login;
	plugin->funcs.on_user_logout = on_user_logout;

	plugin->ptr = data;

	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	co_shutdown((struct restrict_data*) plugin->ptr);
	return 0;
}

