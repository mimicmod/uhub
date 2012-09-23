/*
 * Extras plugin for uhub
 * This plugin is supposed to handle extra features.
 * For example: hub news, friendly hubs (should correspond
 * to the DFAV extension in the future),releases and more. 
 */

#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"
#include <sqlite3.h>
#include "util/memory.h"
#include "util/list.h"
#include "util/config_token.h"
#include "util/cbuffer.h"

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

struct extras_data
{
	sqlite3* db;
	struct plugin_command_handle* command_hubadd_handle;
	struct plugin_command_handle* command_hubdel_handle;
	struct plugin_command_handle* command_hublist_handle;
	struct plugin_command_handle* command_newsadd_handle;
	struct plugin_command_handle* command_newsdel_handle;
	struct plugin_command_handle* command_news_handle;
	struct plugin_command_handle* command_releaseadd_handle;
	struct plugin_command_handle* command_releasedel_handle;
	struct plugin_command_handle* command_releases_handle;  
};

static int null_callback(void* ptr, int argc, char **argv, char **colName) { return 0; }

static int sql_execute(struct extras_data* extrasdata, int (*callback)(void* ptr, int argc, char **argv, char **colName), void* ptr, const char* sql_fmt, ...)
{
	va_list args;
	char query[1024];
	char* errMsg;
	int rc;

	va_start(args, sql_fmt);
	vsnprintf(query, sizeof(query), sql_fmt, args);

	rc = sqlite3_exec(extrasdata->db, query, callback, ptr, &errMsg);
	if (rc != SQLITE_OK)
	{
		sqlite3_free(errMsg);
		return -rc;
	}

	rc = sqlite3_changes(extrasdata->db);
	return rc;
}

static void create_tables(struct plugin_handle* plugin)
{
	const char* table_create = "CREATE TABLE IF NOT EXISTS hubs"
		"("
			"id INTEGER PRIMARY KEY,"
			"hubaddr CHAR NOT NULL,"
			"hubname CHAR NOT NULL"
		");"
		"CREATE TABLE IF NOT EXISTS news"
		"("
			"id INTEGER PRIMARY KEY,"
			"text CHAR NOT NULL,"
			"created TIMESTAMP DEFAULT (DATETIME('NOW'))"
		");"
		"CREATE TABLE IF NOT EXISTS releases"
		"("
			"id INTEGER PRIMARY KEY,"
			"title CHAR NOT NULL,"
			"tth CHAR NOT NULL,"
			"created TIMESTAMP DEFAULT (DATETIME('NOW'))"
		");";

	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	sql_execute(extrasdata, null_callback, NULL, table_create);
}

static struct extras_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct extras_data* data = (struct extras_data*) hub_malloc_zero(sizeof(struct extras_data));
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

static int command_hubadd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	struct plugin_command_arg_data* arg2 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
  
	char* hubaddr = strdup(sql_escape_string(arg1->data.string));
	char* hubname = strdup(sql_escape_string(arg2->data.string));
  
	int rc = sql_execute(extrasdata, null_callback, NULL, "INSERT INTO hubs VALUES(NULL, '%s', '%s');", hubaddr, hubname);
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Added \"%s\" to hublist.", cmd->prefix, hubaddr);
	else
		cbuf_append_format(buf, "*** %s: Unable to add \"%s\" to hublist.", cmd->prefix, hubaddr);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	hub_free(hubaddr);
	hub_free(hubname);

	return 0;
}

static int command_hubdel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	
	int id = args->data.integer;

	int rc = sql_execute(extrasdata, null_callback, NULL, "DELETE FROM hubs WHERE id=%d;", id);
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Deleted hub with id %d.", cmd->prefix, id);
	else
		cbuf_append_format(buf, "*** %s: Unable to delete hub with id %d.", cmd->prefix, id);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_hublist(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	sqlite3_stmt *res;
	int error = 0;
	int rec_count = 0;
	const char *tail;
	char *query = "SELECT * FROM hubs;";

	cbuf_append_format(buf, "*** %s:", cmd->prefix);
	
	error = sqlite3_prepare_v2(extrasdata->db, query, strlen(query), &res, &tail);
	
	while (sqlite3_step(res) == SQLITE_ROW)
	{
		cbuf_append_format(buf, "\nID: %d, Address: %s , Name: \"%s\"\n", sqlite3_column_int(res, 0), (char*) sqlite3_column_text(res, 1), (char*) sqlite3_column_text(res, 2));
		rec_count++;
	}

	if (error != SQLITE_OK || rec_count < 1)
	{
		cbuf_append(buf, " No hubs found in hublist.");
	}

	sqlite3_finalize(res);
	
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	  
	return 0;
}

static int command_newsadd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
  
	const char* news_text = sql_escape_string(arg1->data.string);
  
	int rc = sql_execute(extrasdata, null_callback, NULL, "INSERT INTO news (id, text) VALUES(NULL, '%s');", news_text);
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: News updated.", cmd->prefix);
	else
		cbuf_append_format(buf, "*** %s: Unable to update news.", cmd->prefix);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_newsdel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	
	int id = args->data.integer;

	int rc = sql_execute(extrasdata, null_callback, NULL, "DELETE FROM news WHERE id=%d;", id);
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Deleted news item with id %d.", cmd->prefix, id);
	else
		cbuf_append_format(buf, "*** %s: Unable to delete news item with id %d.", cmd->prefix, id);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_news(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	sqlite3_stmt *res;
	int error = 0;
	int rec_count = 0;
	const char *tail;
	char *query = "SELECT * FROM news;";

	cbuf_append_format(buf, "*** %s:", cmd->prefix);
	
	error = sqlite3_prepare_v2(extrasdata->db, query, strlen(query), &res, &tail);
	
	while (sqlite3_step(res) == SQLITE_ROW)
	{
		cbuf_append_format(buf, "\n[%d] [%s] %s\n", sqlite3_column_int(res, 0), (char*) sqlite3_column_text(res, 2), (char*) sqlite3_column_text(res, 1));
		rec_count++;
	}

	if (error != SQLITE_OK || rec_count < 1)
	{
		cbuf_append(buf, " No news found.");
	}

	sqlite3_finalize(res);
	
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	  
	return 0;
}

static int command_releaseadd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	struct plugin_command_arg_data* arg2 = (struct plugin_command_arg_data*) list_get_next(cmd->args);

	char* tth = strdup(sql_escape_string(arg1->data.string));
	char* title = strdup(sql_escape_string(arg2->data.string));
  
	int rc = sql_execute(extrasdata, null_callback, NULL, "INSERT INTO releases (id, title, tth) VALUES(NULL, '%s', '%s');", title, tth);
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Added \"%s\" to releases.", cmd->prefix, title);
	else
		cbuf_append_format(buf, "*** %s: Unable to add \"%s\" to releases.", cmd->prefix, title);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	hub_free(tth);
	hub_free(title);

	return 0;
}

static int command_releasedel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	
	int id = args->data.integer;

	int rc = sql_execute(extrasdata, null_callback, NULL, "DELETE FROM releases WHERE id=%d;", id);
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Deleted release with id %d.", cmd->prefix, id);
	else
		cbuf_append_format(buf, "*** %s: Unable to delete release with id %d.", cmd->prefix, id);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static int command_releases(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct extras_data* extrasdata = (struct extras_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	sqlite3_stmt *res;
	int error = 0;
	int rec_count = 0;
	const char *tail;
	char *query = "SELECT * FROM releases;";

	cbuf_append_format(buf, "*** %s:", cmd->prefix);
	
	error = sqlite3_prepare_v2(extrasdata->db, query, strlen(query), &res, &tail);
	
	while (sqlite3_step(res) == SQLITE_ROW)
	{
		cbuf_append_format(buf, "\nID: %d\nTitle: %s\nMagnet link: magnet:?xt=urn:tree:tiger:%s\nPublished: %s", sqlite3_column_int(res, 0), (char*) sqlite3_column_text(res, 1), (char*) sqlite3_column_text(res, 2), (char*) sqlite3_column_text(res, 3));
		rec_count++;
	}

	if (error != SQLITE_OK || rec_count < 1)
	{
		cbuf_append(buf, " No releases found.");
	}

	sqlite3_finalize(res);
	
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	  
	return 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct extras_data* extrasdata;
	PLUGIN_INITIALIZE(plugin, "Extras plugin", "0.1", "Plugin for extra features like hub news, releases, hublist.");

	extrasdata = parse_config(config, plugin);

	if (!extrasdata)
		return -1;
  
	extrasdata->command_hubadd_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_hubadd_handle, plugin, "hubadd", "A+m", auth_cred_admin, &command_hubadd, "Add hub to hublist.");
	plugin->hub.command_add(plugin, extrasdata->command_hubadd_handle);

	extrasdata->command_hubdel_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_hubdel_handle, plugin, "hubdel", "N", auth_cred_admin, &command_hubdel, "Delete hub from hublist.");
	plugin->hub.command_add(plugin, extrasdata->command_hubdel_handle);

	extrasdata->command_hublist_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_hublist_handle, plugin, "hublist", "", auth_cred_user, &command_hublist, "List hubs in hublist.");
	plugin->hub.command_add(plugin, extrasdata->command_hublist_handle);

	extrasdata->command_newsadd_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_newsadd_handle, plugin, "newsadd", "+m", auth_cred_admin, &command_newsadd, "Add news item.");
	plugin->hub.command_add(plugin, extrasdata->command_newsadd_handle);

	extrasdata->command_newsdel_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_newsdel_handle, plugin, "newsdel", "N", auth_cred_admin, &command_newsdel, "Delete news item.");
	plugin->hub.command_add(plugin, extrasdata->command_newsdel_handle);

	extrasdata->command_news_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_news_handle, plugin, "news", "", auth_cred_user, &command_news, "Show hubnews.");
	plugin->hub.command_add(plugin, extrasdata->command_news_handle);

	extrasdata->command_releaseadd_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_releaseadd_handle, plugin, "releaseadd", "T+m", auth_cred_admin, &command_releaseadd, "Add release.");
	plugin->hub.command_add(plugin, extrasdata->command_releaseadd_handle);

	extrasdata->command_releasedel_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_releasedel_handle, plugin, "releasedel", "N", auth_cred_admin, &command_releasedel, "Delete release.");
	plugin->hub.command_add(plugin, extrasdata->command_releasedel_handle);

	extrasdata->command_releases_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(extrasdata->command_releases_handle, plugin, "releases", "", auth_cred_user, &command_releases, "Show releases.");
	plugin->hub.command_add(plugin, extrasdata->command_releases_handle);

	plugin->ptr = extrasdata;
	
	create_tables(plugin);
	
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct extras_data* extrasdata;
	set_error_message(plugin, 0);
	extrasdata = (struct extras_data*) plugin->ptr;

	if (extrasdata)
	{
		plugin->hub.command_del(plugin, extrasdata->command_hubadd_handle);
		plugin->hub.command_del(plugin, extrasdata->command_hubdel_handle);
		plugin->hub.command_del(plugin, extrasdata->command_hublist_handle);
		plugin->hub.command_del(plugin, extrasdata->command_newsadd_handle);
		plugin->hub.command_del(plugin, extrasdata->command_newsdel_handle);
		plugin->hub.command_del(plugin, extrasdata->command_news_handle);
		plugin->hub.command_del(plugin, extrasdata->command_releaseadd_handle);
		plugin->hub.command_del(plugin, extrasdata->command_releasedel_handle);
		plugin->hub.command_del(plugin, extrasdata->command_releases_handle);
		
		hub_free(extrasdata->command_hubadd_handle);
		hub_free(extrasdata->command_hubdel_handle);
		hub_free(extrasdata->command_hublist_handle);
		hub_free(extrasdata->command_newsadd_handle);
		hub_free(extrasdata->command_newsdel_handle);
		hub_free(extrasdata->command_news_handle);
		hub_free(extrasdata->command_releaseadd_handle);
		hub_free(extrasdata->command_releasedel_handle);
		hub_free(extrasdata->command_releases_handle);

		sqlite3_close(extrasdata->db);
	}
  
	hub_free(extrasdata);
	return 0;
}
