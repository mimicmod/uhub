/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2012, Jan Vidar Krey
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
#include "plugin_api/command_api.h"
#include "util/memory.h"
#include "util/config_token.h"
#include "util/cbuffer.h"
#include "util/misc.h"
#include "network/ipcalc.h"
#include <sqlite3.h>

struct joins_data
{
	sqlite3* db;
	int srvtdiff;
	enum auth_credentials min_cred;
	enum auth_credentials min_cred_notify;
	struct plugin_command_handle* cmd_joinmsg_handle;
	struct plugin_command_handle* cmd_joinset_handle;
	struct plugin_command_handle* cmd_joinforce_handle;
	struct plugin_command_handle* cmd_joinlist_handle;
};

static int null_callback(void* ptr, int argc, char **argv, char **colName) { return 0; }

static int sql_execute(struct joins_data* sql, int (*callback)(void* ptr, int argc, char **argv, char **colName), void* ptr, const char* sql_fmt, ...)
{
	va_list args;
	char query[1024];
	char* errMsg;
	int rc;

	va_start(args, sql_fmt);
	vsnprintf(query, sizeof(query), sql_fmt, args);

	rc = sqlite3_exec(sql->db, query, callback, ptr, &errMsg);
	if (rc != SQLITE_OK)
	{
		sqlite3_free(errMsg);
		return -rc;
	}

	rc = sqlite3_changes(sql->db);
	return rc;
}

static void create_tables(struct plugin_handle* plugin)
{
	const char* table_create = "CREATE TABLE IF NOT EXISTS joins"
		"("
			"nick CHAR NOT NULL UNIQUE,"
			"message CHAR"
		");";

	struct joins_data* data = (struct joins_data*) plugin->ptr;
	sql_execute(data, null_callback, NULL, table_create);
}

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

static struct joins_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct joins_data* data = (struct joins_data*) hub_malloc_zero(sizeof(struct joins_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
		return 0;

	data->srvtdiff = 0;
	data->min_cred = auth_cred_user;
	data->min_cred_notify = auth_cred_guest;

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

		if (strcmp(cfg_settings_get_key(setting), "file") == 0)
		{
			if (!data->db)
			{
				if (sqlite3_open(cfg_settings_get_value(setting), &data->db))
				{
					cfg_tokens_free(tokens);
					cfg_settings_free(setting);
					hub_free(data);
					set_error_message(plugin, "Unable to open database file");
					return 0;
				}
			}
		}
		else if (strcmp(cfg_settings_get_key(setting), "min_cred") == 0)
		{
			auth_string_to_cred(cfg_settings_get_value(setting), &data->min_cred);
		}
		else if (strcmp(cfg_settings_get_key(setting), "min_cred_notify") == 0)
		{
			auth_string_to_cred(cfg_settings_get_value(setting), &data->min_cred_notify);
		}
		else if (strcmp(cfg_settings_get_key(setting), "server_time_diff") == 0)
		{
			data->srvtdiff = uhub_atoi(cfg_settings_get_value(setting));
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

static struct cbuffer* parse_message(struct joins_data* data, struct plugin_user* user, const char* msg)
{
	struct cbuffer* buf = cbuf_create(strlen(msg));
	const char* start = msg;
	const char* offset = NULL;
	time_t timestamp = time(NULL) + data->srvtdiff * 3600;
	struct tm* now = localtime(&timestamp);

	while ((offset = strchr(start, '%')))
	{
		cbuf_append_bytes(buf, start, (offset - start));

		offset++;
		switch (offset[0])
		{
			case 'n':
				cbuf_append(buf, user->nick);
				break;

			case 'a':
				cbuf_append(buf, ip_convert_to_string(&user->addr));
				break;
			case 'c':
				cbuf_append(buf, auth_cred_to_string(user->credentials));
				break;

			case '%':
				cbuf_append(buf, "%");
				break;

			case 'H':
				cbuf_append_strftime(buf, "%H", now);
				break;

			case 'I':
				cbuf_append_strftime(buf, "%I", now);
				break;

			case 'P':
				cbuf_append_strftime(buf, "%P", now);
				break;

			case 'p':
				cbuf_append_strftime(buf, "%p", now);
				break;

			case 'M':
				cbuf_append_strftime(buf, "%M", now);
				break;

			case 'S':
				cbuf_append_strftime(buf, "%S", now);
				break;
		}

		start = offset + 1;
	}

	if (*start)
		cbuf_append(buf, start);

	return buf;
}

static void send_joinmsg(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct joins_data* data = (struct joins_data*) plugin->ptr;
	struct cbuffer* buf = NULL;

	if (user->credentials >= data->min_cred)
	{
		sqlite3_stmt *res;
		int error = 0;
		const char *tail;
		char query[128];

		sprintf(query, "SELECT message FROM joins WHERE nick='%s' OR nick=' ' ORDER BY nick DESC LIMIT 1;", user->nick);
		error = sqlite3_prepare_v2(data->db, query, strlen(query), &res, &tail);

		if (sqlite3_step(res) == SQLITE_ROW)
		{
			buf = parse_message(data, user, (char*) sqlite3_column_text(res, 0));
			plugin->hub.send_chat(plugin, data->min_cred_notify, auth_cred_admin, cbuf_get(buf));
			cbuf_destroy(buf);
		}

		sqlite3_finalize(res);
	}
}

static void on_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	send_joinmsg(plugin, user);
}

static int command_joinmsg(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct joins_data* data = (struct joins_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	int rc = 0;

	if (arg)
		rc = sql_execute(data, null_callback, NULL, "REPLACE INTO joins VALUES(' ', '%s');", arg->data.string);
	else
		rc = sql_execute(data, null_callback, NULL, "DELETE FROM joins WHERE nick=' ';"); 

	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Successfully %s default join message.", cmd->prefix, arg ? "set" : "deleted");
	else
		cbuf_append_format(buf, "*** %s: Unable to %s default join message.", cmd->prefix, arg ? "set" : "delete");
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_joinforce(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct joins_data* data = (struct joins_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	int rc = 0;

	if (arg2)
		rc = sql_execute(data, null_callback, NULL, "REPLACE INTO joins VALUES('%s','%s');", arg1->data.string, arg2->data.string); 
	else
		rc = sql_execute(data, null_callback, NULL, "DELETE FROM joins WHERE nick='%s';", arg1->data.string); 
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Successfully %s join message for user \"%s\".", cmd->prefix, arg2 ? "set" : "deleted", arg1->data.string);
	else
		cbuf_append_format(buf, "*** %s: Unable to %s join message for user \"%s\".", cmd->prefix, arg2 ? "set" : "delete", arg1->data.string);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_joinset(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct joins_data* data = (struct joins_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	int rc = 0;

	if (arg)
		rc = sql_execute(data, null_callback, NULL, "REPLACE INTO joins VALUES('%s','%s');", user->nick, arg->data.string); 
	else
		rc = sql_execute(data, null_callback, NULL, "DELETE FROM joins WHERE nick='%s';", user->nick); 

	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Successfully %s your join message.", cmd->prefix, arg ? "set" : "deleted");  
	else
		cbuf_append_format(buf, "*** %s: Unable to %s your join message.", cmd->prefix, arg ? "set" : "delete");

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_joinlist(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct joins_data* data = (struct joins_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	sqlite3_stmt *res;
	size_t counter = 0;
	const char *tail;
	char *query = "SELECT * FROM joins ORDER BY nick ASC;";

	cbuf_append_format(buf, "*** %s:", cmd->prefix);

	sqlite3_prepare_v2(data->db, query, strlen(query), &res, &tail);

	while (sqlite3_step(res) == SQLITE_ROW)
	{
		cbuf_append_format(buf, "\n%s\t\"%s\"", (char*) sqlite3_column_text(res, 0), (char*) sqlite3_column_text(res, 1));
		counter++;
	}

	cbuf_append_format(buf, counter > 0 ? "\n" : " No join messages found.");

	sqlite3_finalize(res);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
    
	return 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct joins_data* data;
	PLUGIN_INITIALIZE(plugin, "Joins plugin", "0.1", "Announces user joins to global chat.");

	plugin->funcs.on_user_login = on_user_login;

	data = parse_config(config, plugin);

	if (!data)
		return -1;
  
	data->cmd_joinmsg_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->cmd_joinmsg_handle, plugin, "joinmsg", "?+m", auth_cred_admin, &command_joinmsg, "", "Set/delete default join message.");
	plugin->hub.command_add(plugin, data->cmd_joinmsg_handle);

	data->cmd_joinset_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->cmd_joinset_handle, plugin, "joinset", "?+m", data->min_cred, &command_joinset, "", "Set/delete own join message.");
	plugin->hub.command_add(plugin, data->cmd_joinset_handle);

	data->cmd_joinforce_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->cmd_joinforce_handle, plugin, "joinforce", "m?+m", auth_cred_admin, &command_joinforce, "<nick> [<message>]", "Force/delete join message for a nick.");
	plugin->hub.command_add(plugin, data->cmd_joinforce_handle);

	data->cmd_joinlist_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->cmd_joinlist_handle, plugin, "joinlist", "", auth_cred_admin, &command_joinlist, "", "List join messages.");
	plugin->hub.command_add(plugin, data->cmd_joinlist_handle);

	plugin->ptr = data;
	
	create_tables(plugin);
	
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct joins_data* data;
	set_error_message(plugin, 0);
	data = (struct joins_data*) plugin->ptr;

	if (data)
	{
		plugin->hub.command_del(plugin, data->cmd_joinmsg_handle);
		plugin->hub.command_del(plugin, data->cmd_joinset_handle);
		plugin->hub.command_del(plugin, data->cmd_joinforce_handle);
		plugin->hub.command_del(plugin, data->cmd_joinlist_handle);
		hub_free(data->cmd_joinmsg_handle);
		hub_free(data->cmd_joinset_handle);
		hub_free(data->cmd_joinforce_handle);
		hub_free(data->cmd_joinlist_handle);
		sqlite3_close(data->db);
	}
    
	hub_free(data);
	return 0;
}

