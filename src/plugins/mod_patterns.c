/*
 * Forbidden patterns plugin for uhub
 */

#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"
#include <sqlite3.h>
#include "util/memory.h"
#include "util/list.h"
#include "util/config_token.h"
#include "util/cbuffer.h"
#include "pcre.h"

#define OVECCOUNT 30

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

struct patterns_data
{
	sqlite3* db;
	enum auth_credentials min_cred_protect;
	struct plugin_command_handle* command_patternadd_handle; ///<<< "A handle to the !patternadd command."
	struct plugin_command_handle* command_patterndel_handle; ///<<< "A handle to the !patterndel command."
	struct plugin_command_handle* command_patternlist_handle; ///<<< "A handle to the !patternlist command."
};

static int null_callback(void* ptr, int argc, char **argv, char **colName) { return 0; }

static int sql_execute(struct patterns_data* pdata, int (*callback)(void* ptr, int argc, char **argv, char **colName), void* ptr, const char* sql_fmt, ...)
{
	va_list args;
	char query[1024];
	char* errMsg;
	int rc;

	va_start(args, sql_fmt);
	vsnprintf(query, sizeof(query), sql_fmt, args);

	rc = sqlite3_exec(pdata->db, query, callback, ptr, &errMsg);
	if (rc != SQLITE_OK)
	{
		sqlite3_free(errMsg);
		return -rc;
	}

	rc = sqlite3_changes(pdata->db);
	return rc;
}

/*
  Function to create the patterns table in the given database file.
  No need to create any schema manually if everything goes well,
  sqlite3 should create the file automatically if not present already.
  Called on plugin initialize.
*/

static void create_tables(struct plugin_handle* plugin)
{
	const char* table_create = "CREATE TABLE IF NOT EXISTS patterns(id INTEGER PRIMARY KEY,regexp CHAR NOT NULL,type INT NOT NULL);";
	
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
	sql_execute(pdata, null_callback, NULL, table_create);
}

static struct patterns_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct patterns_data* data = (struct patterns_data*) hub_malloc_zero(sizeof(struct patterns_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
		return 0;

  data->min_cred_protect = auth_cred_none;
  
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
		else if (strcmp(cfg_settings_get_key(setting), "min_cred_protect") == 0)
		{
			auth_string_to_cred(cfg_settings_get_value(setting), &data->min_cred_protect);
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

/*
  Search for a pattern in a message.
  Return values: 0 = not found, 1 = found 
*/

static int pattern_match(const char* haystack, char* needle)
{
  pcre *re;
  const char *error;
  int erroroffset;
  int ovector[OVECCOUNT];
  int rc, status;
  
  status = 0;
  
  re = pcre_compile(needle, 0, &error, &erroroffset, NULL);
  
  if (!re)
  {
    fprintf(stderr, "PCRE compilation failed at expression offset %d: %s\n", erroroffset, error);
  }
  
  rc = pcre_exec(re, NULL, haystack, strlen(haystack), 0, 0, ovector, OVECCOUNT);
  
  if (rc > 0)
  {
    status = 1;
  }
  
  free(re);
  
  return status;
}

/*
  Sweep through all patterns of type mainchat/pm and perform pattern_match
  Return values: 0 = message OK, 1 = message contains forbidden pattern
  Place for some otimization here, can either count found patterns
  and return the count for further use or could stop loop after first match and return 1.
*/

static int check_message(struct patterns_data* pdata, const char* message, int type)
{
  sqlite3_stmt *res;
  char query[50];
  int error = 0;
  int found = 0;
  const char *tail;
  
  int n = sprintf(query, "SELECT * FROM patterns WHERE type=%d;", type);  
  
  error = sqlite3_prepare_v2(pdata->db, query, n, &res, &tail);
  
  while (sqlite3_step(res) == SQLITE_ROW)
  {
    found |= pattern_match(message, (char*) sqlite3_column_text(res, 1));
  }

  sqlite3_finalize(res);
  
  return found;
}

/*
  Perform check on mainchat messages.
*/

static plugin_st check_mainchat(struct plugin_handle* plugin, struct plugin_user* from, const char* message)
{
  struct patterns_data* pdata = (struct patterns_data*) plugin->ptr; 

  if (from->credentials < pdata->min_cred_protect && check_message(pdata, message, 1))
  {    
    plugin->hub.send_status_message(plugin, from, 000, "Your chat message was not sent due to spam detection.");
    return st_deny;
  }
  
  return st_default;
}

/*
  Perform check on private messages.
*/

static plugin_st check_pm(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* message)
{
  struct patterns_data* pdata = (struct patterns_data*) plugin->ptr; 

  if (from->credentials < pdata->min_cred_protect && check_message(pdata, message, 2))
  {    
    plugin->hub.send_status_message(plugin, from, 000, "Your private message was not sent due to spam detection.");
    return st_deny;
  }
  
  return st_default;
}

/*
  Command to add a pattern to the list.
  Useage: !patternadd <number> <regexp>
  (It is not needed to quote ("...") the regular expression.)
  Numbers: 1 = mainchat pattern, 2 = PM pattern
  Optimization to be done: can combine flags to add mainchat and PM pattern at once,
  but there are two ways to store these - seperately with flags 1 and 2 or with combined
  flags, which can slow down checks (more rows selected from DB and flags resolution).
*/

static int command_patternadd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
  struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	struct plugin_command_arg_data* arg2 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
  
  int type = arg1->data.integer;
  char* str = arg2->data.string;
  
  int rc = sql_execute(pdata, null_callback, NULL, "INSERT INTO patterns VALUES(NULL, '%s', %d);", sql_escape_string(str), type);
  
  if (rc > 0)
    cbuf_append_format(buf, "*** %s: Added pattern \"%s\".", cmd->prefix, str);
  else
    cbuf_append_format(buf, "*** %s: Unable to add pattern \"%s\".", cmd->prefix, str);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

/*
  Command to delete a pattern from the list.
  Useage: !patterndel <number>
  Number is the ID of the pattern from !patternlist .
*/

static int command_patterndel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
  struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	
  int id = args->data.integer;

  int rc = sql_execute(pdata, null_callback, NULL, "DELETE FROM patterns WHERE id=%d;", id);
  
  if (rc > 0)
    cbuf_append_format(buf, "*** %s: Deleted pattern with id %d.", cmd->prefix, id);
  else
    cbuf_append_format(buf, "*** %s: Unable to delete pattern with id %d.", cmd->prefix, id);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

/*
  Command to show the list of patterns. Lists ID, type and pattern to be searched for.
  Usage: !patternlist
*/

static int command_patternlist(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
  struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
  struct cbuffer* buf = cbuf_create(128);
  sqlite3_stmt *res;
  int error = 0;
  const char *tail;
  char *query = "SELECT * FROM patterns;";

  cbuf_append_format(buf, "*** %s:\n", cmd->prefix);
  
  error = sqlite3_prepare_v2(pdata->db, query, strlen(query), &res, &tail);
  
  while (sqlite3_step(res) == SQLITE_ROW)
  {
    cbuf_append_format(buf, "ID: %d, Type: %s, Pattern: \"%s\"\n", sqlite3_column_int(res, 0), (char*) sqlite3_column_text(res, 2), (char*) sqlite3_column_text(res, 1));
  }

  sqlite3_finalize(res);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
    
  return 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
  struct patterns_data* pdata;
	PLUGIN_INITIALIZE(plugin, "Forbidden patterns plugin", "0.1", "Searches for forbidden patterns in chat messages.");

  plugin->funcs.on_chat_msg = check_mainchat;
  plugin->funcs.on_private_msg = check_pm;

	pdata = parse_config(config, plugin);

	if (!pdata)
		return -1;
  
	pdata->command_patternadd_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patternadd_handle, plugin, "patternadd", "Nm", auth_cred_admin, &command_patternadd, "Add forbidden pattern.");
	plugin->hub.command_add(plugin, pdata->command_patternadd_handle);

	pdata->command_patterndel_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patterndel_handle, plugin, "patterndel", "N", auth_cred_admin, &command_patterndel, "Delete forbidden pattern.");
	plugin->hub.command_add(plugin, pdata->command_patterndel_handle);
	
	pdata->command_patternlist_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patternlist_handle, plugin, "patternlist", "", auth_cred_admin, &command_patternlist, "List forbidden patterns.");
	plugin->hub.command_add(plugin, pdata->command_patternlist_handle);
	
	plugin->ptr = pdata;
	
	create_tables(plugin);
	
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct patterns_data* pdata;
	set_error_message(plugin, 0);
	pdata = (struct patterns_data*) plugin->ptr;

	if (pdata)
	{
    plugin->hub.command_del(plugin, pdata->command_patternadd_handle);
    plugin->hub.command_del(plugin, pdata->command_patterndel_handle);
    plugin->hub.command_del(plugin, pdata->command_patternlist_handle);
		hub_free(pdata->command_patternadd_handle);
		hub_free(pdata->command_patterndel_handle);
    hub_free(pdata->command_patternlist_handle);		
  	sqlite3_close(pdata->db);
  }
    
	hub_free(pdata);
	return 0;
}