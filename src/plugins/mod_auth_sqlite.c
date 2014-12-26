/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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
#include "util/misc.h"
#include "util/log.h"
#include "util/config_token.h"
#include "util/cbuffer.h"

//#define DEBUG_SQL

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

enum reg_flags
{
	register_self	= 0x01, ///<<< "Enable self-registration"
	notify_ops	= 0x02, ///<<< "Notify ops about success / Send application for registration"
	notify_opchat	= 0x04 ///<<< "Not yet implemented"
};

int reg_flag_get(int flags, enum reg_flags flag)
{
	return flags & flag;
}

struct sql_data
{
	int register_flags;
	sqlite3* db;
	struct plugin_command_handle* command_register_handle; ///<<< "A handle to the !register command."
	struct plugin_command_handle* command_password_handle; ///<<< "A handle to the !password command."
	struct plugin_command_handle* command_useradd_handle; ///<<< "A handle to the !useradd command."
	struct plugin_command_handle* command_userdel_handle; ///<<< "A handle to the !userdel command."
	struct plugin_command_handle* command_usermod_handle; ///<<< "A handle to the !usermod command."
	struct plugin_command_handle* command_userinfo_handle; ///<<< "A handle to the !userinfo command."
	struct plugin_command_handle* command_userpass_handle; ///<<< "A handle to the !userpass command."
	struct plugin_command_handle* command_userlist_handle; ///<<< "A handle to the !userlist command."
	struct plugin_command_handle* command_usercleanup_handle; ///<<< "A handle to the !usercleanup command."
	struct plugin_command_handle* command_ban_handle; ///<<< "A handle to the !ban command."
	struct plugin_command_handle* command_bannick_handle; ///<<< "A handle to the !bannick command."
	struct plugin_command_handle* command_banip_handle; ///<<< "A handle to the !banip command."
	struct plugin_command_handle* command_denynick_handle; ///<<< "A handle to the !denynick command."
	struct plugin_command_handle* command_denyip_handle; ///<<< "A handle to the !denyip command."
	struct plugin_command_handle* command_tempban_handle; ///<<< "A handle to the !tempban command."
	struct plugin_command_handle* command_tempbannick_handle; ///<<< "A handle to the !tempbannick command."
	struct plugin_command_handle* command_tempbanip_handle; ///<<< "A handle to the !tempbanip command."
	struct plugin_command_handle* command_protectip_handle; ///<<< "A handle to the !protectip command."
	struct plugin_command_handle* command_natip_handle; ///<<< "A handle to the !natip command."
	struct plugin_command_handle* command_aclsearch_handle; ///<<< "A handle to the !aclsearch command."
	struct plugin_command_handle* command_acl_handle; ///<<< "A handle to the !acl command."
	struct plugin_command_handle* command_acldel_handle; ///<<< "A handle to the !acldel command."
	struct plugin_command_handle* command_aclcleanup_handle; ///<<< "A handle to the !aclcleanup command."
	struct plugin_command_handle* command_mute_handle; ///<<< "A handle to the !mute command."
	struct plugin_command_handle* command_nopm_handle; ///<<< "A handle to the !nopm command."
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

static void create_tables(struct plugin_handle* plugin)
{
	const char* table_create = "CREATE TABLE IF NOT EXISTS users"
		"("
			"nickname CHAR NOT NULL UNIQUE,"
			"password CHAR NOT NULL,"
			"credentials CHAR NOT NULL DEFAULT 'user',"
			"created TIMESTAMP DEFAULT (DATETIME('NOW')),"
			"activity TIMESTAMP DEFAULT (DATETIME('NOW'))"
		");"
		"CREATE TABLE IF NOT EXISTS acl"
		"("
		  "id INTEGER PRIMARY KEY,"
		  "flags INT,"
			"nickname CHAR,"
			"cid CHAR,"
			"ip_lo CHAR,"
			"ip_hi CHAR,"
			"expiry INT,"
			"who CHAR,"
			"reason TEXT"
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

	data->register_flags = 1;

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
		else if (strcmp(cfg_settings_get_key(setting), "register_flags") == 0)
		{
			data->register_flags = uhub_atoi(cfg_settings_get_value(setting));
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

static int get_user_callback_list(void* ptr, int argc, char **argv, char **colName){
	struct linked_list* users = (struct linked_list*) ptr;
	struct auth_info* data = hub_malloc(sizeof(struct auth_info));
	int i = 0;
	
	memset(data, 0, sizeof(struct auth_info));
	
	for (; i < argc; i++) {
		if (strcmp(colName[i], "nickname") == 0)
			strncpy(data->nickname, argv[i], MAX_NICK_LEN);
		else if (strcmp(colName[i], "password") == 0)
			strncpy(data->password, argv[i], MAX_PASS_LEN);
		else if (strcmp(colName[i], "credentials") == 0)
			auth_string_to_cred(argv[i], &data->credentials);
	}
	
	list_append(users, data);
	
	return 0;
}

static int get_acl_callback(void* ptr, int argc, char **argv, char **colName){
	struct linked_list* matches = (struct linked_list*) ptr;
	struct acl_info* data = hub_malloc(sizeof(struct acl_info));
	int i = 0;
	
	memset(data, 0, sizeof(struct acl_info));
	
	for (; i < argc; i++) {
		if (strcmp(colName[i], "id") == 0)
			data->id = uhub_atoi(argv[i]);
		if (strcmp(colName[i], "flags") == 0)
			data->flags = uhub_atoi(argv[i]);
		else if (strcmp(colName[i], "nickname") == 0)
			strncpy(data->nickname, argv[i], MAX_NICK_LEN);
		else if (strcmp(colName[i], "cid") == 0)
			strncpy(data->cid, argv[i], MAX_CID_LEN);
		else if (strcmp(colName[i], "ip_lo") == 0)
			ip_convert_to_binary(argv[i], &data->ip_addr_lo);
		else if (strcmp(colName[i], "ip_hi") == 0)
			ip_convert_to_binary(argv[i], &data->ip_addr_hi);
		else if (strcmp(colName[i], "expiry") == 0)
		  data->expiry = uhub_atoi(argv[i]);
		else if (strcmp(colName[i], "who") == 0)
			strncpy(data->who, argv[i], MAX_NICK_LEN);
		else if (strcmp(colName[i], "reason") == 0)
			strncpy(data->reason, argv[i], 512);
	}
	
	list_append(matches, data);
	
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

	if (user->credentials >= auth_cred_user)
	{
	  cbuf_append_format(buf, "*** %s: You are already registered.", cmd->prefix);
	  plugin->hub.send_message(plugin, user, cbuf_get(buf));
	}
	else
	{
		if (!reg_flag_get(sql->register_flags, register_self) && reg_flag_get(sql->register_flags, notify_ops))
		{
			cbuf_append_format(buf, "*** %s: Nick=\"%s\" password=\"%s\"", cmd->prefix, data.nickname, data.password);
			plugin->hub.send_chat(plugin, auth_cred_operator, auth_cred_admin, cbuf_get(buf));
			plugin->hub.send_message(plugin, user, "*** register: Your request was sent to our operators.");
		}    
		else if (reg_flag_get(sql->register_flags, register_self))
		{
			if (register_user(plugin, &data) == st_allow)
			{
				cbuf_append_format(buf, "*** %s: User \"%s\" registered.", cmd->prefix, user->nick);
				if (reg_flag_get(sql->register_flags, notify_ops))
					plugin->hub.send_chat(plugin, auth_cred_operator, auth_cred_admin, cbuf_get(buf));
			}
			else
			{
				cbuf_append_format(buf, "*** %s: Unable to register user \"%s\".", cmd->prefix, user->nick);
				if (reg_flag_get(sql->register_flags, notify_ops))
					plugin->hub.send_chat(plugin, auth_cred_operator, auth_cred_admin, cbuf_get(buf));
			}
			plugin->hub.send_message(plugin, user, cbuf_get(buf));
		}
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

	if (get_user(plugin, nick, userinfo) == st_allow)
	{
		if (userinfo->credentials > user->credentials)
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
  
	if (get_user(plugin, nick, userinfo) == st_allow)
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

	if (get_user(plugin, nick, userinfo) == st_allow)
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

	if (get_user(plugin, nick, userinfo) == st_allow)
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

static int command_userlist(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(512);
	struct linked_list* found = (struct linked_list*) list_create();
	
	sql_execute(sql, get_user_callback_list, found, "SELECT * FROM users;");
	
	size_t user_count = list_size(found);
  
	if (!user_count)
		cbuf_append_format(buf, "*** %s: No users found.", cmd->prefix); // Should never happen until admin deletes himself! Shall we allow to delete admin account?
	else
	{
		cbuf_append_format(buf, "*** %s:\n", cmd->prefix);
    
		struct auth_info* list_item;
		list_item = (struct auth_info*) list_get_first(found);
		
		while (list_item)
		{
			cbuf_append_format(buf, "Nickname: %s, Credentials: %s\n", list_item->nickname, auth_cred_to_string(list_item->credentials));
			list_item = (struct auth_info*) list_get_next(found);
		}

		cbuf_append_format(buf, "\n%d entr%s shown\n", user_count, user_count != 1 ? "ies" : "y");
	}

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	list_clear(found, &hub_free);
	list_destroy(found);
	cbuf_destroy(buf);

	return 0;
}

static int command_usercleanup(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_integer);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_credentials);
	int lines = arg1->data.integer;
	enum auth_credentials cred;
	cred = arg2->data.credentials;
	int rc = 0;

	rc = sql_execute(sql, null_callback, NULL, "DELETE FROM users WHERE activity < datetime('NOW', '-%d days') AND credentials='%s';", lines, auth_cred_to_string(cred));
 
	if (!rc)
		cbuf_append_format(buf, "*** %s: Unable to clean users table.", cmd->prefix);
	else
		cbuf_append_format(buf, "*** %s: Cleaned users table.", cmd->prefix);

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
	sql_execute(sql, null_callback, NULL, "VACUUM;");

	return 0;
}

void acl_flag_set(struct acl_info* info, enum acl_flags flag)
{
	info->flags |= flag;
}

int acl_flag_get(struct acl_info* info, enum acl_flags flag)
{
	return info->flags & flag;
}

const char* acl_flag_to_string(enum acl_flags flag)
{
	switch (flag)
	{
		case deny_nickname:	return "DENY NICK";
		case ban_nickname:	return "BAN NICK";
		case ban_cid:		return "BAN CID";
		case ban_ip:		return "BAN IP/RANGE";
		case protect_ip:	return "PROTECT IP/RANGE";
		case deny_ip:		return "DENY IP/RANGE";
		case nat_ip:		return "NAT IP/RANGE";
		case mute_user:		return "MUTE";
		case nopm_user:		return "NOPM";
	}
	
	return "";
}

const char* convert_aclinfo_to_string(struct acl_info* info)
{
	static char aclinfo[1024] = {0, };
	size_t offset = 0;
	size_t len = 0;
	time_t rawtime = info->expiry;
	struct tm* timeinfo;
	char expiry[80];
	char tmp[1024];
	enum acl_flags flag;
	struct linked_list* flags_cast = list_create();
  
	if (rawtime > 0)
	{
		timeinfo = localtime(&rawtime);
		strftime(expiry,80,"\nExpiry: %Y-%m-%d %H:%M:%S",timeinfo);
	}
	else
	{
		strncpy(expiry, "\nExpiry: Permanent", 20);
	}

	len = sprintf(tmp, "\nID: %d", info->id);
	memcpy(aclinfo + offset, tmp, len);
	offset += len;
  
	if (acl_flag_get(info, ban_nickname) || acl_flag_get(info, deny_nickname) || acl_flag_get(info, mute_user) || acl_flag_get(info, nopm_user))
	{
		len = sprintf(tmp, "\nNickname: %s", info->nickname);
		memcpy(aclinfo + offset, tmp, len);
		offset += len;
	}

	if (acl_flag_get(info, ban_cid) || acl_flag_get(info, mute_user) || acl_flag_get(info, nopm_user))
	{
		len = sprintf(tmp, "\nCID: %s", info->cid);
		memcpy(aclinfo + offset, tmp, len);
		offset += len;
	}
  
	if (acl_flag_get(info, ban_ip) || acl_flag_get(info, deny_ip) || acl_flag_get(info, nat_ip) || acl_flag_get(info, protect_ip))
	{
		if (ip_compare(&info->ip_addr_lo, &info->ip_addr_hi) != 0)
		{
			struct ip_range range = {info->ip_addr_lo,info->ip_addr_hi};
			const char* iprange = ip_convert_range_to_string(&range);
			len = sprintf(tmp, "\nIP range: %s", iprange);
			memcpy(aclinfo + offset, tmp, len);
			offset += len;
		}
		else
		{
			const char* ip_lo = ip_convert_to_string(&info->ip_addr_lo);
			len = sprintf(tmp, "\nIP: %s", ip_lo);
			memcpy(aclinfo + offset, tmp, len);
			offset += len;    
		}
	}
  
	len = strlen(expiry);
	memcpy(aclinfo + offset, expiry, len);
	offset += len;

	if (strlen(info->reason) > 0)
	{
		len = sprintf(tmp, "\nReason: %s", info->reason);
		memcpy(aclinfo + offset, tmp, len);
		offset += len;
	}
  
	len = sprintf(tmp, "\nCreated by: %s", info->who);
	memcpy(aclinfo + offset, tmp, len);
	offset += len;
    
	flag = deny_nickname;
  
	while (flag <= nopm_user)
	{
		if(acl_flag_get(info, flag))
		{
			char* flag_str = (char*) acl_flag_to_string(flag);
			list_append(flags_cast, flag_str);
		}
		flag <<= 1;
	}
  
	char* str;  
	str = (char*) list_get_first(flags_cast);

	len = sprintf(tmp, "\nFlags: %s", str);
	memcpy(aclinfo + offset, tmp, len);
	offset += len;
        
	while (str)
	{
		str = (char*) list_get_next(flags_cast);
		if (str != NULL)
		{
			len = sprintf(tmp, " + %s", str);
			memcpy(aclinfo + offset, tmp, len);
			offset += len;
		}  
	}
  
	aclinfo[offset++] = '\n';      
	aclinfo[offset++] = '\0';

	return aclinfo;
}

static plugin_st check_ip_early(struct plugin_handle* plugin, struct ip_addr_encap* addr)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct linked_list* found = (struct linked_list*) list_create();
	struct acl_info* rule;
	size_t matches = 0;
	enum acl_flags flag_protect = protect_ip;
	enum acl_flags flag_deny = deny_ip;
	plugin_st ret = st_default;

	sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE flags = %d;", flag_deny);

	matches = list_size(found);
  
	if (matches)
	{  
		rule = (struct acl_info*) list_get_first(found);

		while (rule && ret != st_deny)
		{
			struct ip_range range1 = {rule->ip_addr_lo, rule->ip_addr_hi};
	    
			if(ip_in_range(addr, &range1))
			{
				ret = st_deny;
			}
			rule = (struct acl_info*) list_get_next(found);
		}

		list_clear(found, &hub_free);
	  
		if (ret == st_deny)
		{
			sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE flags = %d;", flag_protect);
			matches = list_size(found);

			if (matches)
			{
				rule = (struct acl_info*) list_get_first(found);
		      
				while (rule && ret == st_deny)
				{
					struct ip_range range2 = {rule->ip_addr_lo, rule->ip_addr_hi};       
			    
					if(ip_in_range(addr, &range2))
					{
						ret = st_allow;
					}
					rule = (struct acl_info*) list_get_next(found);
				}
			    
				list_clear(found, &hub_free);
			}
		}
	}
  
	list_destroy(found);
    
	return ret;
}

static plugin_st check_ip_late(struct plugin_handle* plugin, struct ip_addr_encap* addr)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct linked_list* found = (struct linked_list*) list_create();
	struct acl_info* rule;
	size_t matches = 0;
	enum acl_flags flag = nat_ip;
	plugin_st ret = st_default;

	sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE flags = %d;", flag);
  
	matches = list_size(found);

	if (matches)
	{
		rule = (struct acl_info*) list_get_first(found);
	  
		while (rule && ret != st_allow)
		{
			struct ip_range range = {rule->ip_addr_lo, rule->ip_addr_hi};
      
			if(ip_in_range(addr, &range))
			{
				ret = st_allow;
			}
			rule = (struct acl_info*) list_get_next(found);
		}
	}
  
	list_clear(found, &hub_free);
	list_destroy(found);
    
	return ret;
}

static plugin_st check_user_late(struct plugin_handle* plugin, struct plugin_user* user, struct acl_info* data)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct linked_list* found = (struct linked_list*) list_create();
	struct acl_info* rule;
	size_t matches = 0;
	enum acl_flags flag_ban = ban_ip;
	enum acl_flags flag_protect = protect_ip;
	plugin_st ret = st_default;

	memset(data, 0, sizeof(struct acl_info));
  
	sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE flags = %d AND (expiry > strftime('%%s','NOW') OR expiry=-1);", flag_ban);
  
	matches = list_size(found);
      
	if (matches)
	{  
		rule = (struct acl_info*) list_get_first(found);

		while (rule && ret != st_deny)
		{
			struct ip_range range1 = {rule->ip_addr_lo, rule->ip_addr_hi};
	    
			if(ip_in_range(&user->addr, &range1))
			{
				memcpy(data, rule, sizeof(struct acl_info));
				ret = st_deny;
			}

			rule = (struct acl_info*) list_get_next(found);
		}

		list_clear(found, &hub_free);
	  
		if (ret == st_deny)
		{
			sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE flags = %d;", flag_protect);
			matches = list_size(found);

			if (matches)
			{
				rule = (struct acl_info*) list_get_first(found);
		      
				while (rule && ret == st_deny)
				{
					struct ip_range range2 = {rule->ip_addr_lo, rule->ip_addr_hi};       
			    
					if(ip_in_range(&user->addr, &range2))
					{
						ret = st_allow;
					}

				rule = (struct acl_info*) list_get_next(found);
				}
			    
				list_clear(found, &hub_free);
			}
		}
	}

	if (ret != st_deny)
	{
		sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE (nickname='%s' OR cid='%s') AND (expiry > strftime('%%s','NOW') OR expiry=-1) LIMIT 1;", sql_escape_string(user->nick), user->cid);    
	  
		matches = list_size(found);
	  
		if (matches)
		{
			rule = (struct acl_info*) list_get_first(found);
			if(!(rule->flags & mute_user) && !(rule->flags & nopm_user))
			{
				memcpy(data, rule, sizeof(struct acl_info));
				ret = st_deny;
			}
		}
	  
		list_clear(found, &hub_free);
	}
  
	list_destroy(found);
    
	return ret;
}

static plugin_st acl_add(struct plugin_handle* plugin, struct acl_info* user)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	unsigned int flags = user->flags;
	char* nick = strdup(sql_escape_string(user->nickname));
	char* cid = strdup(user->cid);
	char* addr_lo = strdup(ip_convert_to_string(&user->ip_addr_lo));
	char* addr_hi = strdup(ip_convert_to_string(&user->ip_addr_hi));
	time_t expiry = user->expiry;
	char* who = strdup(sql_escape_string(user->who));
	char* reason = strdup(sql_escape_string(user->reason));
	int rc = sql_execute(sql, null_callback, NULL, "INSERT INTO acl (id, flags, nickname, cid, ip_lo, ip_hi, expiry, who, reason) VALUES(NULL, '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s');", flags, nick, cid, addr_lo, addr_hi, (int)expiry, who, reason);

	free(nick);
	free(cid);
	free(addr_lo);
	free(addr_hi);
	free(who);
	free(reason);
  
	if (rc <= 0)
	{
		fprintf(stderr, "Unable to add ACL rule \"%s\"\n", convert_aclinfo_to_string(user));
		return st_deny;
	}
	return st_allow;
}

static plugin_st on_chat_message(struct plugin_handle* plugin, struct plugin_user* from, const char* message)
{
	plugin_st ret = st_default;
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct linked_list* found = (struct linked_list*) list_create();
	enum acl_flags flag = mute_user; 

	sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE (nickname='%s' OR cid='%s') AND flags=%d AND expiry > strftime('%%s','NOW');", sql_escape_string(from->nick), from->cid, flag);

	if (list_size(found))
	{    
		ret = st_deny;
	}

	list_clear(found, &hub_free);
	list_destroy(found);
	    
	return ret;
}

static plugin_st on_pm_message(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* message)
{
	plugin_st ret = st_default;
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct linked_list* found = (struct linked_list*) list_create();
	enum acl_flags flag = nopm_user; 

	sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE (nickname='%s' OR cid='%s') AND flags=%d AND expiry > strftime('%%s','NOW');", sql_escape_string(from->nick), from->cid, flag);

	if (list_size(found))
	{    
		ret = st_deny;
	}

	list_clear(found, &hub_free);
	list_destroy(found);
	    
	return ret;
}

static int command_ban(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_user);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	struct plugin_user* target = arg1->data.user;
	char* reason = arg2 ? arg2->data.string : "";  

	if (target == user)
		cbuf_append_format(buf, "*** %s: Cannot ban yourself.", cmd->prefix);
	else if (target->credentials >= user->credentials)
		cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	else
	{
		memset(&data, 0, sizeof(struct acl_info));
		data.flags = 0;
		strncpy(data.nickname, target->nick, MAX_NICK_LEN);
		strncpy(data.cid, target->cid, MAX_CID_LEN);
		strncpy(data.who, user->nick, MAX_NICK_LEN);
		data.expiry = -1;
		strncpy(data.reason, reason, 512);
		data.nickname[MAX_NICK_LEN] = '\0';
		data.cid[MAX_CID_LEN] = '\0';
		data.who[MAX_NICK_LEN] = '\0';
		data.reason[512] = '\0';
        
		acl_flag_set(&data, ban_nickname | ban_cid);
  
		if (acl_add(plugin, &data) == st_allow)
		{
			plugin->hub.user_disconnect(plugin, target);
			cbuf_append_format(buf, "*** %s: User \"%s\" banned.", cmd->prefix, &data.nickname);
		}
		else
			cbuf_append_format(buf, "*** %s: Unable to ban user \"%s\".", cmd->prefix, data.nickname);
	}
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
	return 0;
}

static int command_bannick(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info* userinfo = hub_malloc(sizeof(struct auth_info));
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	char* nick = arg1->data.string;
	char* reason = arg2 ? arg2->data.string : "";  

	if (get_user(plugin, nick, userinfo) == st_allow)
	{
		if (userinfo->credentials >= user->credentials)
			cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	}
	else
	{
		memset(&data, 0, sizeof(struct acl_info));
		data.flags = 0;
		strncpy(data.nickname, nick, MAX_NICK_LEN);
		strncpy(data.who, user->nick, MAX_NICK_LEN);
		data.expiry = -1;
		strncpy(data.reason, reason, 512);
		data.nickname[MAX_NICK_LEN] = '\0';
		data.who[MAX_NICK_LEN] = '\0';
		data.reason[512] = '\0';
      
		acl_flag_set(&data, ban_nickname);
  
		if (acl_add(plugin, &data) == st_allow)
			cbuf_append_format(buf, "*** %s: Nick \"%s\" banned.", cmd->prefix, &data.nickname);
		else
			cbuf_append_format(buf, "*** %s: Unable to ban nick \"%s\".", cmd->prefix, &data.nickname);
	}
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	hub_free(userinfo);
	
	return 0;
}

static int command_banip(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_range);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	struct ip_range* range = arg1->data.range;
	char* reason = arg2 ? arg2->data.string : "";
  
	memset(&data, 0, sizeof(struct acl_info));
	data.flags = 0;
	strncpy(data.who, user->nick, MAX_NICK_LEN);
	data.ip_addr_lo = range->lo;
	data.ip_addr_hi = range->hi;
	data.expiry = -1;
	strncpy(data.reason, reason, 512);
	data.who[MAX_NICK_LEN] = '\0';
	data.reason[512] = '\0';
    
	acl_flag_set(&data, ban_ip);

	if (acl_add(plugin, &data) == st_allow)
	{
		if (ip_compare(&range->lo, &range->hi) != 0)
			cbuf_append_format(buf, "*** %s: IP range \"%s\" banned.", cmd->prefix, ip_convert_range_to_string(range));
		else
			cbuf_append_format(buf, "*** %s: IP \"%s\" banned.", cmd->prefix, ip_convert_to_string(&range->lo));
	}
	else
		cbuf_append_format(buf, "*** %s: Unable to ban IP/range \"%s\".", cmd->prefix, ip_convert_range_to_string(range));

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
	return 0;
}

static int command_denynick(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info* userinfo = hub_malloc(sizeof(struct auth_info));
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	char* nick = arg1->data.string;

	if (get_user(plugin, nick, userinfo) == st_allow)
	{
		if (userinfo->credentials >= user->credentials)
			cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	}
	else
	{
		memset(&data, 0, sizeof(struct acl_info));
		data.flags = 0;
		strncpy(data.nickname, nick, MAX_NICK_LEN);
		strncpy(data.who, user->nick, MAX_NICK_LEN);
		data.expiry = -1;
		data.nickname[MAX_NICK_LEN] = '\0';
		data.who[MAX_NICK_LEN] = '\0';
      
		acl_flag_set(&data, deny_nickname);
  
		if (acl_add(plugin, &data) == st_allow)
			cbuf_append_format(buf, "*** %s: Nick \"%s\" denied.", cmd->prefix, &data.nickname);
		else
			cbuf_append_format(buf, "*** %s: Unable to deny nick \"%s\".", cmd->prefix, &data.nickname);
	}
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	hub_free(userinfo);

	return 0;
}

static int command_denyip(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_range);
	struct ip_range* range = arg1->data.range;
  
	memset(&data, 0, sizeof(struct acl_info));
	data.flags = 0;
	strncpy(data.who, user->nick, MAX_NICK_LEN);
	data.ip_addr_lo = range->lo;
	data.ip_addr_hi = range->hi;
	data.expiry = -1;
	data.who[MAX_NICK_LEN] = '\0';
    
	acl_flag_set(&data, deny_ip);

	if (acl_add(plugin, &data) == st_allow)
	{
		if (ip_compare(&range->lo, &range->hi) != 0)
			cbuf_append_format(buf, "*** %s: IP range \"%s\" denied.", cmd->prefix, ip_convert_range_to_string(range));
		else
			cbuf_append_format(buf, "*** %s: IP \"%s\" denied.", cmd->prefix, ip_convert_to_string(&range->lo));
	}
	else
		cbuf_append_format(buf, "*** %s: Unable to deny IP/range \"%s\".", cmd->prefix, ip_convert_range_to_string(range));

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_tempban(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_user);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_time);
	struct plugin_command_arg_data* arg3 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	struct plugin_user* target = arg1->data.user;
	time_t expiry = arg2->data.time;
	char* reason = arg3 ? arg3->data.string : "";  

	if (target == user)
	{
		cbuf_append_format(buf, "*** %s: Cannot ban yourself.", cmd->prefix);
	}
	else if (target->credentials >= user->credentials)
	{
		cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	}
	else
	{
		memset(&data, 0, sizeof(struct acl_info));
		data.flags = 0;
		strncpy(data.nickname, target->nick, MAX_NICK_LEN);
		strncpy(data.cid, target->cid, MAX_CID_LEN);
		strncpy(data.who, user->nick, MAX_NICK_LEN);
		data.expiry = time(0) + expiry;
		strncpy(data.reason, reason, 512);
		data.nickname[MAX_NICK_LEN] = '\0';
		data.cid[MAX_CID_LEN] = '\0';
		data.who[MAX_NICK_LEN] = '\0';
		data.reason[512] = '\0';
        
		acl_flag_set(&data, ban_nickname | ban_cid);
  
		if (acl_add(plugin, &data) == st_allow)
		{
			plugin->hub.user_disconnect(plugin, target);
			cbuf_append_format(buf, "*** %s: User \"%s\" banned.", cmd->prefix, &data.nickname);
		}
		else
			cbuf_append_format(buf, "*** %s: Unable to ban user \"%s\".", cmd->prefix, data.nickname);
	}
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
	return 0;
}

static int command_tempbannick(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info* userinfo = hub_malloc(sizeof(struct auth_info));
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_time);
	struct plugin_command_arg_data* arg3 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	char* nick = arg1->data.string;
	time_t expiry = arg2->data.time;
	char* reason = arg3 ? arg3->data.string : "";  

	if (get_user(plugin, nick, userinfo) == st_allow)
	{
		if (userinfo->credentials >= user->credentials)
			cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	}
	else
	{
		memset(&data, 0, sizeof(struct acl_info));
		data.flags = 0;
		strncpy(data.nickname, nick, MAX_NICK_LEN);
		strncpy(data.who, user->nick, MAX_NICK_LEN);
		data.expiry = time(NULL) + expiry;
		strncpy(data.reason, reason, 512);
		data.nickname[MAX_NICK_LEN] = '\0';
		data.who[MAX_NICK_LEN] = '\0';
		data.reason[512] = '\0';

		acl_flag_set(&data, ban_nickname);
  
		if (acl_add(plugin, &data) == st_allow)
			cbuf_append_format(buf, "*** %s: Nick \"%s\" banned.", cmd->prefix, &data.nickname);
		else
			cbuf_append_format(buf, "*** %s: Unable to ban nick \"%s\".", cmd->prefix, &data.nickname);
	}
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	hub_free(userinfo);
	
	return 0;
}

static int command_tempbanip(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_range);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_time);
	struct plugin_command_arg_data* arg3 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	struct ip_range* range = arg1->data.range;
	time_t expiry = arg2->data.time;
	char* reason = arg3 ? arg3->data.string : "";
  
	memset(&data, 0, sizeof(struct acl_info));
	data.flags = 0;
	strncpy(data.who, user->nick, MAX_NICK_LEN);
	data.ip_addr_lo = range->lo;
	data.ip_addr_hi = range->hi;
	data.expiry = time(NULL) + expiry;
	strncpy(data.reason, reason, 512);
	data.who[MAX_NICK_LEN] = '\0';
	data.reason[512] = '\0';

	acl_flag_set(&data, ban_ip);

	if (acl_add(plugin, &data) == st_allow)
	{
		if (ip_compare(&range->lo, &range->hi) != 0)
			cbuf_append_format(buf, "*** %s: IP range \"%s\" banned.", cmd->prefix, ip_convert_range_to_string(range));
		else
			cbuf_append_format(buf, "*** %s: IP \"%s\" banned.", cmd->prefix, ip_convert_to_string(&range->lo));
	}
	else
		cbuf_append_format(buf, "*** %s: Unable to ban IP/range \"%s\".", cmd->prefix, ip_convert_range_to_string(range));

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
	return 0;
}

static int command_acl(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(512);
	struct linked_list* found = (struct linked_list*) list_create();
	
	sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl;");
	
	size_t acl_count = list_size(found);
  
	if (!acl_count)
		cbuf_append_format(buf, "*** %s: No ACL rules found.", cmd->prefix);
	else
	{
		cbuf_append_format(buf, "*** %s:\n", cmd->prefix);
	  
		struct acl_info* rule;
		rule = (struct acl_info*) list_get_first(found);

		while (rule)
		{
			cbuf_append_format(buf, "%s", convert_aclinfo_to_string(rule));
			rule = (struct acl_info*) list_get_next(found);
		}

		cbuf_append_format(buf, "\n%d entr%s shown\n", acl_count, acl_count != 1 ? "ies" : "y");
	}

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	list_clear(found, &hub_free);
	list_destroy(found);
	cbuf_destroy(buf);

	return 0;
}

static int command_aclsearch(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(512);
	struct linked_list* found = (struct linked_list*) list_create();
	struct plugin_command_arg_data* arg = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	char* search = arg->data.string;
	struct ip_range range;
	int rc = 0;
	int searchtype = 0;
	
	cbuf_append_format(buf, "*** %s: Searching for \"%s\".\n", cmd->prefix, search);
	
	if (ip_convert_address_to_range(search, &range))
	{
		const char* addr_lo = strdup(ip_convert_to_string(&range.lo));
		const char* addr_hi = strdup(ip_convert_to_string(&range.hi));
	  
		if (ip_compare(&range.lo, &range.hi) != 0)
			rc = sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE ip_lo='%s' AND ip_hi='%s';", addr_lo, addr_hi);
		else
		{
			rc = sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE flags > 4;");
			searchtype = 1;
		}
	}
	else
		rc = sql_execute(sql, get_acl_callback, found, "SELECT * FROM acl WHERE nickname='%s' OR cid='%s';", sql_escape_string(search), search);
	
	size_t acl_count = list_size(found);
  
	if (!rc || !acl_count)
		cbuf_append(buf, "No ACL rules found.");
	else
	{ 
		struct acl_info* rule;
		rule = (struct acl_info*) list_get_first(found);

		while (rule)
		{ 
			if (searchtype == 1)
			{
				struct ip_range rule_range = {rule->ip_addr_lo, rule->ip_addr_hi};

				if(ip_in_range(&range.lo, &rule_range))
				{
					cbuf_append_format(buf, "%s", convert_aclinfo_to_string(rule));
				}
			}
			else
			{
				cbuf_append_format(buf, "%s", convert_aclinfo_to_string(rule));      
			}
	    
			rule = (struct acl_info*) list_get_next(found);
		}

		cbuf_append_format(buf, "\n%d entr%s shown\n", acl_count, acl_count != 1 ? "ies" : "y");
	}

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	list_clear(found, &hub_free);
	list_destroy(found);
	cbuf_destroy(buf);

	return 0;
}

static int command_acldel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	
	int id = args->data.integer;

	int rc = sql_execute(sql, null_callback, NULL, "DELETE FROM acl WHERE id=%d;", id);
	
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Deleted ACL rule with id %d.", cmd->prefix, id);
	else
		cbuf_append_format(buf, "*** %s: Unable to delete ACL rule with id %d.", cmd->prefix, id);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_aclcleanup(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	int rc = 0;
	
	rc = sql_execute(sql, null_callback, NULL, "DELETE FROM acl WHERE expiry BETWEEN 0 AND strftime('%%s', 'NOW');");
 
	if (!rc)
		cbuf_append_format(buf, "*** %s: Unable to clean ACL table.", cmd->prefix);
	else
	{
		cbuf_append_format(buf, "*** %s: Cleaned ACL table.", cmd->prefix);
	}

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	sql_execute(sql, null_callback, NULL, "VACUUM;");

	return 0;
}

static int command_protectip(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_range);
	struct ip_range* range = arg1->data.range;
  
	memset(&data, 0, sizeof(struct acl_info));
	data.flags = 0;
	strncpy(data.who, user->nick, MAX_NICK_LEN);
	data.ip_addr_lo = range->lo;
	data.ip_addr_hi = range->hi;
	data.expiry = -1;
	data.who[MAX_NICK_LEN] = '\0';

	acl_flag_set(&data, protect_ip);

	if (acl_add(plugin, &data) == st_allow)
	{
		if (ip_compare(&range->lo, &range->hi) != 0)
			cbuf_append_format(buf, "*** %s: Added protected IP range \"%s\".", cmd->prefix, ip_convert_range_to_string(range));
		else
			cbuf_append_format(buf, "*** %s: Added protected IP \"%s\".", cmd->prefix, ip_convert_to_string(&range->lo));
	}
	else
		cbuf_append_format(buf, "*** %s: Unable to add protected IP/range \"%s\".", cmd->prefix, ip_convert_range_to_string(range));

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
	return 0;
}

static int command_natip(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_range);
	struct ip_range* range = arg1->data.range;
  
	memset(&data, 0, sizeof(struct acl_info));
	data.flags = 0;
	strncpy(data.who, user->nick, MAX_NICK_LEN);
	data.ip_addr_lo = range->lo;
	data.ip_addr_hi = range->hi;
	data.expiry = -1;
	data.who[MAX_NICK_LEN] = '\0';

	acl_flag_set(&data, nat_ip);

	if (acl_add(plugin, &data) == st_allow)
	{
		if (ip_compare(&range->lo, &range->hi) != 0)
			cbuf_append_format(buf, "*** %s: Added NAT IP range \"%s\".", cmd->prefix, ip_convert_range_to_string(range));
		else
			cbuf_append_format(buf, "*** %s: Added NAT IP \"%s\".", cmd->prefix, ip_convert_to_string(&range->lo));
	}
	else
		cbuf_append_format(buf, "*** %s: Unable to add NAT IP/range \"%s\".", cmd->prefix, ip_convert_range_to_string(range));

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
	return 0;
}

static int command_mute(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_user);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_time);
	struct plugin_user* target = arg1->data.user;
	time_t expiry = arg2 ? arg2->data.time : 86400;  

	if (target == user)
		cbuf_append_format(buf, "*** %s: Cannot mute yourself.", cmd->prefix);
	else if (target->credentials >= user->credentials)
		cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	else
	{
		memset(&data, 0, sizeof(struct acl_info));
		data.flags = 0;
		strncpy(data.nickname, target->nick, MAX_NICK_LEN);
		strncpy(data.cid, target->cid, MAX_CID_LEN);
		strncpy(data.who, user->nick, MAX_NICK_LEN);
		data.expiry = time(NULL) + expiry;
		data.nickname[MAX_NICK_LEN] = '\0';
		data.cid[MAX_CID_LEN] = '\0';
		data.who[MAX_NICK_LEN] = '\0';

		acl_flag_set(&data, mute_user);
  
		if (acl_add(plugin, &data) == st_allow)
			cbuf_append_format(buf, "*** %s: User \"%s\" is now unable to send chat messages.", cmd->prefix, &data.nickname);
		else
			cbuf_append_format(buf, "*** %s: Unable to mute user \"%s\".", cmd->prefix, data.nickname);
	}
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
	return 0;
}

static int command_nopm(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct acl_info data;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_user);
	struct plugin_command_arg_data* arg2 = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_time);
	struct plugin_user* target = arg1->data.user;
	time_t expiry = arg2 ? arg2->data.time : 86400;  

	if (target == user)
		cbuf_append_format(buf, "*** %s: Cannot mute yourself.", cmd->prefix);
	else if (target->credentials >= user->credentials)
		cbuf_append_format(buf, "*** %s: Insufficient rights.", cmd->prefix);
	else
	{
		memset(&data, 0, sizeof(struct acl_info));
		data.flags = 0;
		strncpy(data.nickname, target->nick, MAX_NICK_LEN);
		strncpy(data.cid, target->cid, MAX_CID_LEN);
		strncpy(data.who, user->nick, MAX_NICK_LEN);
		data.expiry = time(NULL) + expiry;
		data.nickname[MAX_NICK_LEN] = '\0';
		data.cid[MAX_CID_LEN] = '\0';
		data.who[MAX_NICK_LEN] = '\0';

		acl_flag_set(&data, nopm_user);
  
		if (acl_add(plugin, &data) == st_allow)
			cbuf_append_format(buf, "*** %s: User \"%s\" is now unable to send private messages.", cmd->prefix, &data.nickname);
		else
			cbuf_append_format(buf, "*** %s: Unable to nopm user \"%s\".", cmd->prefix, data.nickname);
	}
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	
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
			fprintf(stderr, "Unable to update login stats for user \"%s\"\n", user->nick);
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
	plugin->funcs.on_check_ip_early = check_ip_early;
	plugin->funcs.on_check_ip_late = check_ip_late;
	plugin->funcs.on_check_user_late = check_user_late;
	plugin->funcs.on_chat_msg = on_chat_message;
	plugin->funcs.on_private_msg = on_pm_message;
	
	// Log functions
	plugin->funcs.on_user_login = update_user_activity;

	sql = parse_config(config, plugin);

	if (!sql)
		return -1;

	if (sql->register_flags > 0)
	{
		sql->command_register_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
		PLUGIN_COMMAND_INITIALIZE(sql->command_register_handle, plugin, "register", "p", auth_cred_guest, &command_register, "Register your username.");
		plugin->hub.command_add(plugin, sql->command_register_handle);
	}

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

	sql->command_userlist_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_userlist_handle, plugin, "userlist", "", auth_cred_operator, &command_userlist, "Show list of all registered users.");
	plugin->hub.command_add(plugin, sql->command_userlist_handle);

	sql->command_usercleanup_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_usercleanup_handle, plugin, "usercleanup", "NC", auth_cred_admin, &command_usercleanup, "Delete inactive user accounts.");
	plugin->hub.command_add(plugin, sql->command_usercleanup_handle);

	sql->command_ban_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_ban_handle, plugin, "ban", "u?+m", auth_cred_super, &command_ban, "Ban user (must be logged in).");
	plugin->hub.command_add(plugin, sql->command_ban_handle);

	sql->command_bannick_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_bannick_handle, plugin, "bannick", "n?+m", auth_cred_super, &command_bannick, "Ban nick.");
	plugin->hub.command_add(plugin, sql->command_bannick_handle);

	sql->command_banip_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_banip_handle, plugin, "banip", "r?+m", auth_cred_super, &command_banip, "Ban IP/range.");
	plugin->hub.command_add(plugin, sql->command_banip_handle);

	sql->command_denynick_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_denynick_handle, plugin, "denynick", "n", auth_cred_admin, &command_denynick, "Add restricted nickname.");
	plugin->hub.command_add(plugin, sql->command_denynick_handle);

	sql->command_denyip_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_denyip_handle, plugin, "denyip", "r", auth_cred_admin, &command_denyip, "Add restricted IP/range.");
	plugin->hub.command_add(plugin, sql->command_denyip_handle);

	sql->command_tempban_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_tempban_handle, plugin, "tempban", "ut?+m", auth_cred_operator, &command_tempban, "Temporarily ban user (must be logged in).");
	plugin->hub.command_add(plugin, sql->command_tempban_handle);

	sql->command_tempbannick_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_tempbannick_handle, plugin, "tempbannick", "nt?+m", auth_cred_operator, &command_tempbannick, "Temporarily ban nick.");
	plugin->hub.command_add(plugin, sql->command_tempbannick_handle);

	sql->command_tempbanip_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_tempbanip_handle, plugin, "tempbanip", "rt?+m", auth_cred_operator, &command_tempbanip, "Temporarily ban IP/range.");
	plugin->hub.command_add(plugin, sql->command_tempbanip_handle);

	sql->command_protectip_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_protectip_handle, plugin, "protectip", "r", auth_cred_admin, &command_protectip, "Protect IP/range against bans.");
	plugin->hub.command_add(plugin, sql->command_protectip_handle);

	sql->command_natip_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_natip_handle, plugin, "natip", "r", auth_cred_admin, &command_natip, "Add NAT IP/range.");
	plugin->hub.command_add(plugin, sql->command_natip_handle);

	sql->command_mute_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_mute_handle, plugin, "mute", "u?t", auth_cred_operator, &command_mute, "Disallow a user to send chat messages.");
	plugin->hub.command_add(plugin, sql->command_mute_handle);

	sql->command_nopm_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_nopm_handle, plugin, "nopm", "u?t", auth_cred_operator, &command_nopm, "Disallow a user to send private messages.");
	plugin->hub.command_add(plugin, sql->command_nopm_handle);

	sql->command_acl_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_acl_handle, plugin, "acl", "", auth_cred_operator, &command_acl, "List all ACL rules.");
	plugin->hub.command_add(plugin, sql->command_acl_handle);

	sql->command_aclsearch_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_aclsearch_handle, plugin, "aclsearch", "m", auth_cred_operator, &command_aclsearch, "Search in ACL list for a value.");
	plugin->hub.command_add(plugin, sql->command_aclsearch_handle);

	sql->command_acldel_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_acldel_handle, plugin, "acldel", "N", auth_cred_operator, &command_acldel, "Remove ACL rule.");
	plugin->hub.command_add(plugin, sql->command_acldel_handle);

	sql->command_aclcleanup_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(sql->command_aclcleanup_handle, plugin, "aclcleanup", "", auth_cred_admin, &command_aclcleanup, "Delete expired ACL rules.");
	plugin->hub.command_add(plugin, sql->command_aclcleanup_handle);

	plugin->ptr = sql;
	
	create_tables(plugin);
	
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct sql_data* sql;
	set_error_message(plugin, 0);
	sql = (struct sql_data*) plugin->ptr;

	if (sql)
	{
		if (sql->register_flags > 0)
		{
			plugin->hub.command_del(plugin, sql->command_register_handle);
		}
		plugin->hub.command_del(plugin, sql->command_password_handle);
		plugin->hub.command_del(plugin, sql->command_useradd_handle);
		plugin->hub.command_del(plugin, sql->command_userdel_handle);
		plugin->hub.command_del(plugin, sql->command_usermod_handle);
		plugin->hub.command_del(plugin, sql->command_userinfo_handle);
		plugin->hub.command_del(plugin, sql->command_userpass_handle);
		plugin->hub.command_del(plugin, sql->command_ban_handle);
		plugin->hub.command_del(plugin, sql->command_bannick_handle);
		plugin->hub.command_del(plugin, sql->command_banip_handle);
		plugin->hub.command_del(plugin, sql->command_denynick_handle);
		plugin->hub.command_del(plugin, sql->command_denyip_handle);
		plugin->hub.command_del(plugin, sql->command_tempban_handle);
		plugin->hub.command_del(plugin, sql->command_tempbanip_handle);
		plugin->hub.command_del(plugin, sql->command_tempbannick_handle);
		plugin->hub.command_del(plugin, sql->command_protectip_handle);
		plugin->hub.command_del(plugin, sql->command_natip_handle);
		plugin->hub.command_del(plugin, sql->command_mute_handle);
		plugin->hub.command_del(plugin, sql->command_nopm_handle);
		plugin->hub.command_del(plugin, sql->command_aclsearch_handle);
		plugin->hub.command_del(plugin, sql->command_acl_handle);
		plugin->hub.command_del(plugin, sql->command_acldel_handle);
		plugin->hub.command_del(plugin, sql->command_usercleanup_handle);
		plugin->hub.command_del(plugin, sql->command_aclcleanup_handle);
		plugin->hub.command_del(plugin, sql->command_userlist_handle);

		hub_free(sql->command_register_handle);
		hub_free(sql->command_password_handle);
		hub_free(sql->command_useradd_handle);
		hub_free(sql->command_userdel_handle);
		hub_free(sql->command_usermod_handle);
		hub_free(sql->command_userinfo_handle);
		hub_free(sql->command_userpass_handle);
		hub_free(sql->command_ban_handle);
		hub_free(sql->command_bannick_handle);
		hub_free(sql->command_banip_handle);
		hub_free(sql->command_denynick_handle);
		hub_free(sql->command_denyip_handle);
		hub_free(sql->command_tempban_handle);
		hub_free(sql->command_tempbanip_handle);
		hub_free(sql->command_tempbannick_handle);
		hub_free(sql->command_protectip_handle);
		hub_free(sql->command_natip_handle);
		hub_free(sql->command_mute_handle);
		hub_free(sql->command_nopm_handle);
		hub_free(sql->command_aclsearch_handle);
		hub_free(sql->command_acl_handle);
		hub_free(sql->command_acldel_handle);
		hub_free(sql->command_usercleanup_handle);
		hub_free(sql->command_aclcleanup_handle);
		hub_free(sql->command_userlist_handle);

		sqlite3_close(sql->db);
	}
  
	hub_free(sql);
	return 0;
}
