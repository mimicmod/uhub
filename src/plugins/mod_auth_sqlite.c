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
#include <sqlite3.h>
#include "util/memory.h"
#include "util/list.h"
#include "util/ipcalc.h"
#include "util/misc.h"
#include "util/log.h"
#include "util/config_token.h"
#include "util/cbuffer.h"

// #define DEBUG_SQL

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

struct sql_data
{
	int register_self;
	sqlite3* db;
	struct plugin_command_handle* command_register_handle; ///<<< "A handle to the !register command."
	struct plugin_command_handle* command_password_handle; ///<<< "A handle to the !password command."
	struct plugin_command_handle* command_useradd_handle; ///<<< "A handle to the !useradd command."
	struct plugin_command_handle* command_userdel_handle; ///<<< "A handle to the !userdel command."
  struct plugin_command_handle* command_usermod_handle; ///<<< "A handle to the !usermod command."
	struct plugin_command_handle* command_userinfo_handle; ///<<< "A handle to the !userinfo command."
  struct plugin_command_handle* command_userpass_handle; ///<<< "A handle to the !userpass command."
};

static int null_callback(void* ptr, int argc, char **argv, char **colName) { return 0; }

static int sql_execute(struct sql_data* sql, int (*callback)(void* ptr, int argc, char **argv, char **colName), void* ptr, const char* sql_fmt, ...)
{
	va_list args;
	char query[1024];
	char* errMsg;
	int rc;

	va_start(args, sql_fmt);
	vsnprintf(query, sizeof(query), sql_fmt, args);

#ifdef DEBUG_SQL
	printf("SQL: %s\n", query);
#endif

	rc = sqlite3_exec(sql->db, query, callback, ptr, &errMsg);
	if (rc != SQLITE_OK)
	{
#ifdef DEBUG_SQL
		fprintf(stderr, "ERROR: %s\n", errMsg);
#endif
		sqlite3_free(errMsg);
		return -rc;
	}

	rc = sqlite3_changes(sql->db);
	return rc;
}

static void create_users_table(struct plugin_handle* plugin)
{
	const char* table_create = "CREATE TABLE IF NOT EXISTS users"
		"("
			"nickname CHAR NOT NULL UNIQUE,"
			"password CHAR NOT NULL,"
			"credentials CHAR NOT NULL DEFAULT 'user',"
			"created TIMESTAMP DEFAULT (DATETIME('NOW')),"
			"activity TIMESTAMP DEFAULT (DATETIME('NOW'))"
		");";
	
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	sql_execute(sql, null_callback, NULL, table_create);
}

static struct sql_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct sql_data* data = (struct sql_data*) hub_malloc_zero(sizeof(struct sql_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
		return 0;

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
		else if (strcmp(cfg_settings_get_key(setting), "register_self") == 0)
		{
			if (!string_to_boolean(cfg_settings_get_value(setting), &data->register_self))
				data->register_self = 1;
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

	if (!data->db)
	{
	      set_error_message(plugin, "No database file is given, use file=<database>");
	      hub_free(data);
	      return 0;
	}
	return data;
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

struct data_record {
	struct auth_info* data;
	int found;
};

static int get_user_callback(void* ptr, int argc, char **argv, char **colName){
	struct data_record* data = (struct data_record*) ptr;
	int i = 0;
	for (; i < argc; i++) {
		if (strcmp(colName[i], "nickname") == 0)
			strncpy(data->data->nickname, argv[i], MAX_NICK_LEN);
		else if (strcmp(colName[i], "password") == 0)
			strncpy(data->data->password, argv[i], MAX_PASS_LEN);
		else if (strcmp(colName[i], "credentials") == 0)
		{
			auth_string_to_cred(argv[i], &data->data->credentials);
			data->found = 1;
		}
	}

#ifdef DEBUG_SQL
	printf("SQL: nickname=%s, password=%s, credentials=%s\n", data->data->nickname, data->data->password, auth_cred_to_string(data->data->credentials));
#endif
	return 0;
}

static plugin_st get_user(struct plugin_handle* plugin, const char* nickname, struct auth_info* data)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct data_record result;
	char query[1024];
	char* errMsg;
	int rc;

	snprintf(query, sizeof(query), "SELECT * FROM users WHERE nickname='%s';", sql_escape_string(nickname));
	memset(data, 0, sizeof(struct auth_info));

	result.data = data;
	result.found = 0;

#ifdef DEBUG_SQL
	printf("SQL: %s\n", query);
#endif

	rc = sqlite3_exec(sql->db, query , get_user_callback, &result, &errMsg);
	if (rc != SQLITE_OK) {
#ifdef DEBUG_SQL
		fprintf(stderr, "SQL: ERROR: %s\n", errMsg);
#endif
		sqlite3_free(errMsg);
		return st_default;
	}
	
	if (result.found)
		return st_allow;
	return st_default;
}

static plugin_st register_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	char* nick = strdup(sql_escape_string(user->nickname));
	char* pass = strdup(sql_escape_string(user->password));
	const char* cred = auth_cred_to_string(user->credentials);
	int rc = sql_execute(sql, null_callback, NULL, "INSERT INTO users (nickname, password, credentials) VALUES('%s', '%s', '%s');", nick, pass, cred);

	free(nick);
	free(pass);

	if (rc <= 0)
	{
		fprintf(stderr, "Unable to add user \"%s\"\n", user->nickname);
		return st_deny;
	}
	return st_allow;
	
}

static plugin_st update_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;

	char* nick = strdup(sql_escape_string(user->nickname));
	char* pass = strdup(sql_escape_string(user->password));
	const char* cred = auth_cred_to_string(user->credentials);
	int rc = sql_execute(sql, null_callback, NULL, "UPDATE users SET password='%s', credentials='%s' WHERE nickname='%s';", pass, cred, nick);

	free(nick);
	free(pass);

	if (rc <= 0)
	{
		fprintf(stderr, "Unable to update user \"%s\"\n", user->nickname);
		return st_deny;
	}
	return st_allow;
	
}

static plugin_st delete_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;

	char* nick = strdup(sql_escape_string(user->nickname));
	int rc = sql_execute(sql, null_callback, NULL, "DELETE FROM users WHERE nickname='%s';", nick);

	free(nick);

	if (rc <= 0)
	{
		fprintf(stderr, "Unable to delete user \"%s\"\n", user->nickname);
		return st_deny;
	}
	return st_allow;
}

static int command_register(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
  struct auth_info data;
  struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
  char* password = args->data.string;
  
  strncpy(data.nickname, user->nick, MAX_NICK_LEN);
  strncpy(data.password, password, MAX_PASS_LEN);
  data.nickname[MAX_NICK_LEN] = '\0';
  data.password[MAX_PASS_LEN] = '\0';
  data.credentials = auth_cred_user; 	

  if (sql->register_self == 0)
	{
    cbuf_append_format(buf, "*** %s: Nick=\"%s\" password=\"%s\"", cmd->prefix, data.nickname, data.password);
    plugin->hub.send_chat(plugin, auth_cred_operator, auth_cred_admin, cbuf_get(buf));
    plugin->hub.send_message(plugin, user, "*** register: Your request was sent to our operators.");
	}
  else
  {    
    if (user->credentials >= auth_cred_user)
      cbuf_append_format(buf, "*** %s: You are already registered.", cmd->prefix);
    else
    {
      if (register_user(plugin, &data) == st_allow)
      	cbuf_append_format(buf, "*** %s: User \"%s\" registered.", cmd->prefix, user->nick);
      else
      	cbuf_append_format(buf, "*** %s: Unable to register user \"%s\".", cmd->prefix, user->nick);
    }
    plugin->hub.send_message(plugin, user, cbuf_get(buf));
  }

  cbuf_destroy(buf);
	return 0;
}

static int command_password(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info data;
	struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	char* password = args->data.string;

	strncpy(data.nickname, user->nick, MAX_NICK_LEN);
	strncpy(data.password, password, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = user->credentials;

	if (update_user(plugin, &data) == st_allow)
		cbuf_append_format(buf, "*** %s: Password changed.", cmd->prefix);
	else
		cbuf_append_format(buf, "*** %s: Unable to change password for user \"%s\".", cmd->prefix, user->nick);

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_useradd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info data;
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	struct plugin_command_arg_data* arg2 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
  char* nick = arg1->data.string;
	char* password = arg2->data.string;
	enum auth_credentials credentials;
	
	credentials = auth_cred_user;

	strncpy(data.nickname, nick, MAX_NICK_LEN);
	strncpy(data.password, password, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = credentials;

	if (register_user(plugin, &data) == st_allow)
		cbuf_append_format(buf, "*** %s: User \"%s\" registered.", cmd->prefix, nick);
	else
		cbuf_append_format(buf, "*** %s: Unable to register user \"%s\".", cmd->prefix, nick);

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_userdel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info data;
	struct auth_info* userinfo = hub_malloc(sizeof(struct auth_info));
	struct plugin_command_arg_data* arg = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	char* nick = arg->data.string;

	get_user(plugin, nick, userinfo);
	if (userinfo)
	{
	  if (userinfo->credentials >= user->credentials)
	    cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	  else
	  {
  	  strncpy(data.nickname, nick, MAX_NICK_LEN);
  	  data.nickname[MAX_NICK_LEN] = '\0';
  
	    if (delete_user(plugin, &data) == st_allow)
		    cbuf_append_format(buf, "*** %s: User \"%s\" deleted.", cmd->prefix, nick);
	    else
		    cbuf_append_format(buf, "*** %s: Unable to delete user \"%s\".", cmd->prefix, nick);
    }
  }
	
  plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	hub_free(userinfo);
	
  return 0;
}

static int command_usermod(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info data;
	struct auth_info* userinfo = hub_malloc(sizeof(struct auth_info));
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	struct plugin_command_arg_data* arg2 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
	char* nick = arg1->data.string;
	enum auth_credentials credentials = arg2->data.credentials;
  
	get_user(plugin, nick, userinfo);
	if (userinfo)
	{
		strncpy(data.password, userinfo->password, MAX_PASS_LEN);
	  strncpy(data.nickname, nick, MAX_NICK_LEN);
	  data.nickname[MAX_NICK_LEN] = '\0';
	  data.password[MAX_PASS_LEN] = '\0';
	  data.credentials = credentials;

  	if (update_user(plugin, &data) == st_allow)
  		cbuf_append_format(buf, "*** %s: Credentials of user \"%s\" changed from \"%s\" to \"%s\".", cmd->prefix, nick, auth_cred_to_string(userinfo->credentials), auth_cred_to_string(data.credentials));  		
  	else
  	  cbuf_append_format(buf, "*** %s: Unable to change credentials for user \"%s\".", cmd->prefix, nick);
	}
	else
		cbuf_append_format(buf, "*** %s: Unable to find user \"%s\".", cmd->prefix, nick);

  plugin->hub.send_message(plugin, user, cbuf_get(buf));
  cbuf_destroy(buf);
	hub_free(userinfo);
	
	return 0;
}

static int command_userinfo(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info* userinfo = hub_malloc(sizeof(struct auth_info));
	struct plugin_command_arg_data* arg = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	char* nick = arg->data.string;

	get_user(plugin, nick, userinfo);
	if (userinfo)
		cbuf_append_format(buf, "*** %s: Nick: %s, Credentials: %s", cmd->prefix, nick, auth_cred_to_string(userinfo->credentials));
	else
		cbuf_append_format(buf, "*** %s: Unable to find user \"%s\".", cmd->prefix, nick);
		
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
  hub_free(userinfo);

	return 0;
}

static int command_userpass(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info data;
	struct auth_info* userinfo = hub_malloc(sizeof(struct auth_info));
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	struct plugin_command_arg_data* arg2 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
  char* nick = arg1->data.string;
	char* password = arg2->data.string;
		
	get_user(plugin, nick, userinfo);
	if (userinfo)
	{
	  if (userinfo->credentials >= user->credentials)
	    cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	  else
	  {
  		data.credentials = userinfo->credentials;
  	  strncpy(data.nickname, nick, MAX_NICK_LEN);
  	  strncpy(data.password, password, MAX_PASS_LEN);
  	  data.nickname[MAX_NICK_LEN] = '\0';
  	  data.password[MAX_PASS_LEN] = '\0';
  
      if (update_user(plugin, &data) == st_allow)
      	cbuf_append_format(buf, "*** %s: Password for user \"%s\" changed.", cmd->prefix, nick);
      else
      	cbuf_append_format(buf, "*** %s: Unable to change password for user \"%s\".", cmd->prefix, nick);
    }
  }
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
  hub_free(userinfo);
  
	return 0;
}

static void update_user_activity(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	if (user->credentials > auth_cred_guest)
	{
	  char* nick = strdup(sql_escape_string(user->nick));
  	int rc = sql_execute(sql, null_callback, NULL, "UPDATE users SET activity=DATETIME('NOW') WHERE nickname='%s';", nick);
  
  	free(nick);
  
  	if (rc <= 0)
  	{
  		fprintf(stderr, "Unable to update login stats for user \"%s\"\n", user->nick);
  	}
  }
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
  struct sql_data* sql;
	PLUGIN_INITIALIZE(plugin, "SQLite authentication plugin", "1.0", "Authenticate users based on a SQLite database.");

	// Authentication actions.
	plugin->funcs.auth_get_user = get_user;
	plugin->funcs.auth_register_user = register_user;
	plugin->funcs.auth_update_user = update_user;
	plugin->funcs.auth_delete_user = delete_user;
	plugin->funcs.on_user_login = update_user_activity;

	sql = parse_config(config, plugin);

	if (!sql)
		return -1;

	sql->command_register_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_register_handle, plugin, "register", "p", auth_cred_guest, &command_register, "Register your username.");
	plugin->hub.command_add(plugin, sql->command_register_handle);

	sql->command_password_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_password_handle, plugin, "password", "p", auth_cred_user, &command_password, "Change your own password.");
	plugin->hub.command_add(plugin, sql->command_password_handle);

	sql->command_useradd_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_useradd_handle, plugin, "useradd", "np", auth_cred_operator, &command_useradd, "Register a new user.");
	plugin->hub.command_add(plugin, sql->command_useradd_handle);

	sql->command_userdel_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_userdel_handle, plugin, "userdel", "n", auth_cred_operator, &command_userdel, "Delete a registered user.");
	plugin->hub.command_add(plugin, sql->command_userdel_handle);
	
	sql->command_userinfo_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_userinfo_handle, plugin, "userinfo", "n", auth_cred_operator, &command_userinfo, "Show registered user info.");
	plugin->hub.command_add(plugin, sql->command_userinfo_handle);

	sql->command_usermod_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_usermod_handle, plugin, "usermod", "nC", auth_cred_admin, &command_usermod, "Modify user credentials.");
	plugin->hub.command_add(plugin, sql->command_usermod_handle);

	sql->command_userpass_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_userpass_handle, plugin, "userpass", "np", auth_cred_operator, &command_userpass, "Change password for a user.");
	plugin->hub.command_add(plugin, sql->command_userpass_handle);
	
	plugin->ptr = sql;
	
	create_users_table(plugin);
	
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct sql_data* sql;
	set_error_message(plugin, 0);
	sql = (struct sql_data*) plugin->ptr;

	if (sql)
	{
    plugin->hub.command_del(plugin, sql->command_register_handle);
    plugin->hub.command_del(plugin, sql->command_password_handle);
    plugin->hub.command_del(plugin, sql->command_useradd_handle);
    plugin->hub.command_del(plugin, sql->command_userdel_handle);
    plugin->hub.command_del(plugin, sql->command_usermod_handle);
    plugin->hub.command_del(plugin, sql->command_userinfo_handle);
    plugin->hub.command_del(plugin, sql->command_userpass_handle);
		hub_free(sql->command_register_handle);
		hub_free(sql->command_password_handle);
		hub_free(sql->command_useradd_handle);
		hub_free(sql->command_userdel_handle);
		hub_free(sql->command_usermod_handle);
		hub_free(sql->command_userinfo_handle);
		hub_free(sql->command_userpass_handle);		
  	sqlite3_close(sql->db);
  }
  
	hub_free(sql);
	return 0;
}