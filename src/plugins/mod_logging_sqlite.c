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

#include "system.h"
#include "adc/adcconst.h"
#include "adc/sid.h"
#include "util/memory.h"
#include "network/ipcalc.h"
#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"
#include "util/misc.h"
#include "util/config_token.h"
#include "util/list.h"
#include "util/cbuffer.h"
#include <sqlite3.h>

struct ip_addr_encap;

struct log_data
{
	sqlite3* db;
	int srvtdiff;
	struct plugin_command_handle* command_userlog_handle; ///<<< "A handle to the !userlog command."
	struct plugin_command_handle* command_userlogcleanup_handle; ///<<< "A handle to the !userlogcleanup command."
};

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

static struct log_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct log_data* data = (struct log_data*) hub_malloc_zero(sizeof(struct log_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	uhub_assert(data != NULL);

	data->srvtdiff = 0;

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

static int null_callback(void* ptr, int argc, char **argv, char **colName) { return 0; }

static int sql_execute(struct log_data* ldata, int (*callback)(void* ptr, int argc, char **argv, char **colName), void* ptr, const char* sql_fmt, ...)
{
	va_list args;
	char query[1024];
	char* errMsg;
	int rc;

	va_start(args, sql_fmt);
	vsnprintf(query, sizeof(query), sql_fmt, args);

	rc = sqlite3_exec(ldata->db, query, callback, ptr, &errMsg);
	if (rc != SQLITE_OK)
	{
		sqlite3_free(errMsg);
		return -rc;
	}

	rc = sqlite3_changes(ldata->db);
	return rc;
}

static const char* sql_escape_string(const char* str)
{
	static char out[1024];
	size_t i = 0;
	size_t n = 0;
	for (; n < strlen(str); n++)
	{
		if (str[n] == '\'')
			out[i++] = '\'';
		out[i++] = str[n];
	}
	out[i++] = '\0';
	return out;
}
static int check_column(const char* col)
{
	char* columns[7];
	int i = 0;
	columns[0] = "nick";
	columns[1] = "cid";
	columns[2] = "addr";
	columns[3] = "credentials";
	columns[4] = "useragent";
	columns[5] = "message";
	columns[6] = "time";
	int found = 0;

	for (; i < 7;i++)
	{
		if(strcmp(col, columns[i]) == 0)
		{
			found++;
			break;
		}
	}

	return found;
}

static void create_tables(struct plugin_handle* plugin)
{
	const char* table_create = "CREATE TABLE IF NOT EXISTS userlog"
		"("
			"nick CHAR,"
			"cid CHAR,"
			"addr CHAR,"
			"credentials CHAR,"
			"useragent CHAR,"
			"message CHAR,"
			"time TIMESTAMP DEFAULT (DATETIME('NOW'))"
		");";

	struct log_data* data = (struct log_data*) plugin->ptr;
	sql_execute(data, null_callback, NULL, table_create);
}

static void log_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct log_data* ldata = (struct log_data*) plugin->ptr;
	const char* cred = auth_cred_to_string(user->credentials);
	const char* addr = ip_convert_to_string(&user->addr);
	char* nick = strdup(sql_escape_string(user->nick));
	char* uagent = strdup(sql_escape_string(user->user_agent));

	int rc = sql_execute(ldata, null_callback, NULL, "INSERT INTO userlog VALUES('%s', '%s', '%s', '%s', '%s', 'LoginOK', DATETIME('NOW', 'localtime', '%d hours'));", nick, user->cid, addr, cred, uagent, ldata->srvtdiff);

	if (rc < 0)
		fprintf(stderr, "[SQLITE LOG] Unable to log: LoginOK %s/%s %s \"%s\" (%s) \"%s\"\n", sid_to_string(user->sid), user->cid, addr, user->nick, cred, user->user_agent);

	hub_free(nick);
	hub_free(uagent);
}

static void log_user_login_error(struct plugin_handle* plugin, struct plugin_user* user, const char* reason)
{
	struct log_data* ldata = (struct log_data*) plugin->ptr;
	const char* addr = ip_convert_to_string(&user->addr);
	char* nick = strdup(sql_escape_string(user->nick));
	char* uagent = strdup(sql_escape_string(user->user_agent));

	int rc = sql_execute(ldata, null_callback, NULL, "INSERT INTO userlog VALUES('%s', '%s', '%s', '', '%s', 'LoginError (%s)', DATETIME('NOW', 'localtime', '%d hours'));", nick, user->cid, addr, uagent, reason, ldata->srvtdiff);

	if (rc < 0)
		fprintf(stderr, "[SQLITE LOG] Unable to log: LoginError %s/%s %s \"%s\" (%s) \"%s\"\n", sid_to_string(user->sid), user->cid, addr, user->nick, reason, user->user_agent);

	hub_free(nick);
	hub_free(uagent);
}

static void log_user_logout(struct plugin_handle* plugin, struct plugin_user* user, const char* reason)
{
	struct log_data* ldata = (struct log_data*) plugin->ptr;
	const char* addr = ip_convert_to_string(&user->addr);
	char* nick = strdup(sql_escape_string(user->nick));
	char* uagent = strdup(sql_escape_string(user->user_agent));

	int rc = sql_execute(ldata, null_callback, NULL, "INSERT INTO userlog VALUES('%s', '%s', '%s', '', '%s', '%s (%s)', DATETIME('NOW', 'localtime', '%d hours'));", nick, user->cid, addr, uagent, "Logout", reason, ldata->srvtdiff);

	if (rc < 0)
		fprintf(stderr, "[SQLITE LOG] Unable to log: Logout %s/%s %s \"%s\" (%s) \"%s\"\n", sid_to_string(user->sid), user->cid, addr, user->nick, reason, user->user_agent);

	hub_free(nick);
	hub_free(uagent);
}

static void log_change_nick(struct plugin_handle* plugin, struct plugin_user* user, const char* new_nick)
{
	struct log_data* ldata = (struct log_data*) plugin->ptr;
	const char* addr = ip_convert_to_string(&user->addr);
	char* nick = strdup(sql_escape_string(user->nick));

	int rc = sql_execute(ldata, null_callback, NULL, "INSERT INTO userlog VALUES('', '%s', '%s', '', '', '%s (%s -> %s)', DATETIME('NOW', 'localtime', '%d hours'));", user->cid, addr, "NickChange", nick, new_nick, ldata->srvtdiff);

	if (rc < 0)
		fprintf(stderr, "[SQLITE LOG] Unable to log: NickChange %s/%s %s \"%s\" -> \"%s\"\n", sid_to_string(user->sid), user->cid, addr, user->nick, new_nick);

	hub_free(nick);
}

static int command_userlog(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct log_data* ldata = (struct log_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_integer);
	struct plugin_command_arg_data* arg3 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	int lines = arg1 ? arg1->data.integer : 20;
	char* column = arg2 ? arg2->data.string : "";
	char* search = arg3 ? arg3->data.string : "";
	size_t column_len = strlen(column);
	size_t search_len = strlen(search);
	char query[1024];
	sqlite3_stmt *res;
	int error = 0;
	const char *tail;
	size_t count = 0;

	if (lines > 200)
		lines = 200;

	if (search_len)
	{
		if (column_len)
		{
			if(!check_column(column))
			{
				cbuf_append_format(buf, "*** %s: Invalid column. Valid columns are nick, cid, addr, credentials, useragent, message, time.\n", cmd->prefix);
				sqlite3_finalize(res);
				plugin->hub.send_message(plugin, user, cbuf_get(buf));
				cbuf_destroy(buf);
				return 0;
			}
			if (strcmp(column, "message") == 0)
			{
				sprintf(query, "SELECT * FROM userlog WHERE message LIKE '%%%s%%' ORDER BY time DESC LIMIT %d;", search, lines);
				cbuf_append_format(buf, "*** %s: Searching for \"%s\" in column \"message\".\n", cmd->prefix, search);
			}
			else
			{
				sprintf(query, "SELECT * FROM userlog WHERE %s='%s' ORDER BY time DESC LIMIT %d;", column, search, lines);
				cbuf_append_format(buf, "*** %s: Searching for \"%s\" in column \"%s\".\n", cmd->prefix, search, column);
			}
		}
		else 
		{
			sprintf(query, "SELECT * FROM userlog WHERE nick='%s' OR cid='%s' OR credentials='%s' OR useragent='%s' OR addr='%s' OR message LIKE '%%%s%%' ORDER BY time DESC LIMIT %d;", search, search, search, search, search, search, lines);
			cbuf_append_format(buf, "*** %s: Searching for \"%s\" in all columns.\n", cmd->prefix, search);
		}
	}
	else
	{
		sprintf(query, "SELECT * FROM userlog ORDER BY time DESC LIMIT %d;", lines);
		cbuf_append_format(buf, "*** %s: ", cmd->prefix);
	}

	error = sqlite3_prepare_v2(ldata->db, query, strlen(query), &res, &tail);
    
	while (sqlite3_step(res) == SQLITE_ROW)
	{
		cbuf_append_format(buf, "[%s] %s, %s [%s] [%s] \"%s\" - %s\n", (char*) sqlite3_column_text(res, 6), (char*) sqlite3_column_text(res, 1), (char*) sqlite3_column_text(res, 0), (char*) sqlite3_column_text(res, 3), (char*) sqlite3_column_text(res, 2), (char*) sqlite3_column_text(res, 4), (char*) sqlite3_column_text(res, 5));
		count++;
	}

	if (error || count == 0)
		cbuf_append(buf, "No log entries found.\n");
	else
		cbuf_append_format(buf, "\n%zd entr%s shown\n", count, count != 1 ? "ies" : "y");

	sqlite3_finalize(res);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
    
	return 0;
}

static int command_userlogcleanup(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct log_data* ldata = (struct log_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	
	int days = arg->data.integer;

	int rc = sql_execute(ldata, null_callback, NULL, "DELETE FROM userlog WHERE time < DATETIME('NOW', 'localtime', '-%d days');", days);
	
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Cleaned log entries older than %d days.", cmd->prefix, days);
	else
		cbuf_append_format(buf, "*** %s: Unable to clean log table.", cmd->prefix);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	sql_execute(ldata, null_callback, NULL, "VACUUM;");

	return 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "SQLite logging plugin", "0.4", "Logs users entering and leaving the hub to SQLite database.");

	struct log_data* ldata;

	plugin->funcs.on_user_login = log_user_login;
	plugin->funcs.on_user_login_error = log_user_login_error;
	plugin->funcs.on_user_logout = log_user_logout;
	plugin->funcs.on_user_nick_change = log_change_nick;

	ldata = parse_config(config, plugin);

	if (!ldata)
		return -1;

	ldata->command_userlog_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(ldata->command_userlog_handle, plugin, "userlog", "?N?m?m", auth_cred_operator, &command_userlog, "Search in userlog for a value.");
	plugin->hub.command_add(plugin, ldata->command_userlog_handle);

	ldata->command_userlogcleanup_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(ldata->command_userlogcleanup_handle, plugin, "userlogcleanup", "N", auth_cred_admin, &command_userlogcleanup, "Delete log entries.");
	plugin->hub.command_add(plugin, ldata->command_userlogcleanup_handle);

	plugin->ptr = ldata;

	create_tables(plugin);

	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct log_data* ldata = (struct log_data*) plugin->ptr;

	if (ldata)
	{
		sqlite3_close(ldata->db);

		plugin->hub.command_del(plugin, ldata->command_userlog_handle);
		plugin->hub.command_del(plugin, ldata->command_userlogcleanup_handle);
		hub_free(ldata->command_userlog_handle);
		hub_free(ldata->command_userlogcleanup_handle);
		hub_free(ldata);
	}

	return 0;
}
