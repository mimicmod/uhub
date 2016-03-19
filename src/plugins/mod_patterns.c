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

enum pattern_types
{
	mc = 0x01,
	pm = 0x02,
	ni = 0x03,
	ua = 0x04
};

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

struct patterns_data
{
	sqlite3* db;
	struct plugin_command_handle* command_patternadd_handle; ///<<< "A handle to the !patternadd command."
	struct plugin_command_handle* command_patterndel_handle; ///<<< "A handle to the !patterndel command."
	struct plugin_command_handle* command_patternlist_handle; ///<<< "A handle to the !patternlist command."
	struct plugin_command_handle* command_patternexadd_handle; ///<<< "A handle to the !patternexadd command."
	struct plugin_command_handle* command_patternexdel_handle; ///<<< "A handle to the !patternexdel command."
	struct plugin_command_handle* command_patternexlist_handle; ///<<< "A handle to the !patternexlist command."
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
 * Function to create the patterns table in the given database file.
 * No need to create any schema manually if everything goes well,
 * sqlite3 should create the file automatically if not present already.
 * Called on plugin initialize.
 */

static void create_tables(struct plugin_handle* plugin)
{
	const char* table_create = "CREATE TABLE IF NOT EXISTS patterns(id INTEGER PRIMARY KEY,regexp CHAR NOT NULL,type INT NOT NULL,min_cred_protect CHAR NOT NULL DEFAULT('user')); CREATE TABLE IF NOT EXISTS pattern_exceptions(id INTEGER PRIMARY KEY,regexp CHAR NOT NULL,pattern_id INT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,min_cred_protect CHAR NOT NULL DEFAULT('guest'));";
	
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

/*
 * Search for a pattern in a message.
 * @return: 0 = not found, 1 = found 
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

static int check_exception(struct patterns_data* pdata, const char* message, int pattern_id, enum auth_credentials credentials)
{
	sqlite3_stmt *res;
	char query[50];
	int error = 0;
	int exception = 0;
	const char *tail;
	enum auth_credentials cred;

	int n = sprintf(query, "SELECT * FROM pattern_exceptions WHERE pattern_id=%d;", pattern_id);

	error = sqlite3_prepare_v2(pdata->db, query, n, &res, &tail);

	while (sqlite3_step(res) == SQLITE_ROW)
	{
		auth_string_to_cred((char*) sqlite3_column_text(res, 3), &cred);
		if (cred <= credentials && pattern_match(message, (char*) sqlite3_column_text(res, 1)))
		{
			exception = 1;
		}
	}

	sqlite3_finalize(res);

	return exception;
}

/*
 * Sweep through all patterns of type mainchat/pm and perform pattern_match
 * @return: 0 = message OK, 1 = message contains forbidden pattern
 * TODO: Count found patterns or list matches and send back to user.
 */

static int check_message(struct patterns_data* pdata, const char* message, enum pattern_types type, enum auth_credentials credentials)
{
	sqlite3_stmt *res;
	char query[50];
	int error = 0;
	int found = 0;
	int exception = 0;
	const char *tail;
	enum auth_credentials cred;

	int n = sprintf(query, "SELECT * FROM patterns WHERE type=%d;", type);

	error = sqlite3_prepare_v2(pdata->db, query, n, &res, &tail);

	while (sqlite3_step(res) == SQLITE_ROW)
	{
		auth_string_to_cred((char*) sqlite3_column_text(res, 3), &cred);
		if (cred > credentials)
		{
			found |= pattern_match(message, (char*) sqlite3_column_text(res, 1));
			if (found)
			{
				exception |= check_exception(pdata, message, sqlite3_column_int(res, 0), credentials);
			}
		}
	}

	sqlite3_finalize(res);

	if (!exception && found)
		return 1;

	return 0;
}

/*
 * Perform check on mainchat messages.
 */

static plugin_st check_mainchat(struct plugin_handle* plugin, struct plugin_user* from, const char* message)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr; 
	enum pattern_types t = mc;
	
	if (check_message(pdata, message, t, from->credentials))
	{    
		plugin->hub.send_status_message(plugin, from, 000, "Your chat message was not sent due to spam detection.");
		return st_deny;
	}

	return st_default;
}

/*
 * Perform check on private messages.
 */

static plugin_st check_pm(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* message)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
	enum pattern_types t = pm;

	if (check_message(pdata, message, t, from->credentials))
	{    
		plugin->hub.send_status_message(plugin, from, 000, "Your private message was not sent due to spam detection.");
		return st_deny;
	}

	return st_default;
}

static plugin_st check_user_info(struct plugin_handle* plugin, struct plugin_user* user, struct acl_info* data)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
	enum pattern_types t = ni;
	enum acl_flags f = deny_nickname;

	memset(data, 0, sizeof(struct acl_info));
	
	if (check_message(pdata, user->nick, t, user->credentials))
	{    
		plugin->hub.send_status_message(plugin, user, 000, "Your nickname matches a forbidden pattern.");
		return st_deny;
	}
	
	t = ua;
	
	if (check_message(pdata, user->user_agent, t, user->credentials))
	{    
		plugin->hub.send_status_message(plugin, user, 000, "Your client matches a forbidden pattern.");
		return st_deny;
	}

	return st_default;
}

const char* pattern_type_to_string(enum pattern_types type)
{
	switch (type)
	{
		case mc:	return "MC";
		case pm:	return "PM";
		case ni:	return "NI";
		case ua:	return "UA";
	}

	return "";
};

int pattern_string_to_type(const char* str, enum pattern_types* out)
{
	if (!str || !*str || !out)
		return 0;

	if (!strcasecmp(str, "mc")) { *out = mc; return 1; }
	if (!strcasecmp(str, "pm")) { *out = pm; return 1; }
	if (!strcasecmp(str, "ni")) { *out = ni; return 1; }
	if (!strcasecmp(str, "ua")) { *out = ua; return 1; }
	return 0;
}

/*
 * Command to add a pattern to the list.
 * Useage: !patternadd <message type> <exception> <min protected credentials> <regexp>
 * (It is not needed to quote ("...") the regular expression.)
 * Message type: 1 = mainchat pattern, 2 = PM pattern
 */

static int command_patternadd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	struct plugin_command_arg_data* arg2 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
	struct plugin_command_arg_data* arg3 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
  
	char* t = arg1->data.string;
	enum pattern_types type;
	
	if (!pattern_string_to_type(t, &type))
	{
		cbuf_append_format(buf, "*** %s: Wrong pattern type \"%s\". Available types are: MC, PM, NI, UA.", cmd->prefix, t);
	}
	else
	{
		enum auth_credentials cred = arg2->data.credentials;
		char* str = arg3->data.string;
	  
		int rc = sql_execute(pdata, null_callback, NULL, "INSERT INTO patterns VALUES(NULL, '%s', %d, '%s');", sql_escape_string(str), type, auth_cred_to_string(cred));
	  
		if (rc > 0)
			cbuf_append_format(buf, "*** %s: Added pattern \"%s\".", cmd->prefix, str);
		else
			cbuf_append_format(buf, "*** %s: Unable to add pattern \"%s\".", cmd->prefix, str);
	}
	
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

/*
 * Command to delete a pattern from the list (related exceptions included).
 * Usage: !patterndel <ID>
 * ID is the pattern ID from !patternlist .
 */

static int command_patterndel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	
	int id = args->data.integer;

	int rc = sql_execute(pdata, null_callback, NULL, "PRAGMA foreign_keys=ON; DELETE FROM patterns WHERE id=%d;", id);
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Deleted pattern with id %d.", cmd->prefix, id);
	else
		cbuf_append_format(buf, "*** %s: Unable to delete pattern with id %d.", cmd->prefix, id);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

/*
 * Command to show the list of patterns. Lists ID, type and pattern to be searched for.
 * Usage: !patternlist
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
		cbuf_append_format(buf, "ID: %d, Type: %s, Pattern: \"%s\", Protected credentials: %s\n", sqlite3_column_int(res, 0), pattern_type_to_string((enum pattern_types) sqlite3_column_int(res, 2)), (char*) sqlite3_column_text(res, 1), (char*) sqlite3_column_text(res, 3));
	}

	sqlite3_finalize(res);

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

/*
 * Command to add a pattern exception to the list.
 * Usage: !patternexadd <pattern ID> <min protected credentials> <regexp>
 * Min protected credentials: set this minimally one level lower than related pattern min. protected credentials otherwise exception will not work.
 * Still this can prevent lowest user levels to send forbidden patterns.
 * Pattern ID: ID of a pattern to which the exception is related.
 */

static int command_patternexadd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg1 = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	struct plugin_command_arg_data* arg2 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
	struct plugin_command_arg_data* arg3 = (struct plugin_command_arg_data*) list_get_next(cmd->args);
  
	int pattern_id = arg1->data.integer;
	enum auth_credentials cred = arg2->data.credentials;
	char* str = arg3->data.string;
  
	int rc = sql_execute(pdata, null_callback, NULL, "PRAGMA foreign_keys=ON; INSERT INTO pattern_exceptions VALUES(NULL, '%s', %d, '%s');", sql_escape_string(str), pattern_id, auth_cred_to_string(cred));
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Added pattern exception \"%s\" to pattern ID %d.", cmd->prefix, str, pattern_id);
	else
		cbuf_append_format(buf, "*** %s: Unable to add pattern exception \"%s\" to pattern ID %d.", cmd->prefix, str, pattern_id);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

/*
 * Command to delete a pattern exception from the list.
 * Useage: !patternexdel <ID>
 * ID is the pattern exception ID from !patternexlist .
 */

static int command_patternexdel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* args = (struct plugin_command_arg_data*) list_get_first(cmd->args);
	
	int id = args->data.integer;

	int rc = sql_execute(pdata, null_callback, NULL, "DELETE FROM pattern_exceptions WHERE id=%d;", id);
  
	if (rc > 0)
		cbuf_append_format(buf, "*** %s: Deleted pattern exception with ID %d.", cmd->prefix, id);
	else
		cbuf_append_format(buf, "*** %s: Unable to delete pattern exception with id %d.", cmd->prefix, id);
  
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

/*
 * Command to show the list of pattern exceptions. Lists ID, pattern ID which is exception related to.
 * Usage: !patternexlist
 */

static int command_patternexlist(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct patterns_data* pdata = (struct patterns_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	sqlite3_stmt *res;
	int error = 0;
	const char *tail;
	char *query = "SELECT * FROM pattern_exceptions;";

	cbuf_append_format(buf, "*** %s:\n", cmd->prefix);

	error = sqlite3_prepare_v2(pdata->db, query, strlen(query), &res, &tail);

	while (sqlite3_step(res) == SQLITE_ROW)
	{
		cbuf_append_format(buf, "ID: %d, Pattern ID: %d, Exception pattern: \"%s\", Min. credentials for exception: %s\n", sqlite3_column_int(res, 0), sqlite3_column_int(res, 2), (char*) sqlite3_column_text(res, 1), (char*) sqlite3_column_text(res, 3));
	}

	sqlite3_finalize(res);

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct patterns_data* pdata;
	PLUGIN_INITIALIZE(plugin, "Forbidden patterns plugin", "0.3", "Searches for forbidden patterns in chat messages and user info.");

	plugin->funcs.on_chat_msg = check_mainchat;
	plugin->funcs.on_private_msg = check_pm;
	plugin->funcs.on_check_user_late = check_user_info;

	pdata = parse_config(config, plugin);

	if (!pdata)
		return -1;
  
	pdata->command_patternadd_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patternadd_handle, plugin, "patternadd", "mC+m", auth_cred_admin, &command_patternadd, "Add forbidden pattern.");
	plugin->hub.command_add(plugin, pdata->command_patternadd_handle);

	pdata->command_patterndel_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patterndel_handle, plugin, "patterndel", "N", auth_cred_admin, &command_patterndel, "Delete forbidden pattern.");
	plugin->hub.command_add(plugin, pdata->command_patterndel_handle);
	
	pdata->command_patternlist_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patternlist_handle, plugin, "patternlist", "", auth_cred_super, &command_patternlist, "List forbidden patterns.");
	plugin->hub.command_add(plugin, pdata->command_patternlist_handle);

	pdata->command_patternexadd_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patternexadd_handle, plugin, "patternexadd", "NC+m", auth_cred_admin, &command_patternexadd, "Add exception to a forbidden pattern.");
	plugin->hub.command_add(plugin, pdata->command_patternexadd_handle);

	pdata->command_patternexdel_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patternexdel_handle, plugin, "patternexdel", "N", auth_cred_admin, &command_patternexdel, "Delete pattern exception.");
	plugin->hub.command_add(plugin, pdata->command_patternexdel_handle);
	
	pdata->command_patternexlist_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(pdata->command_patternexlist_handle, plugin, "patternexlist", "", auth_cred_super, &command_patternexlist, "List pattern exceptions.");
	plugin->hub.command_add(plugin, pdata->command_patternexlist_handle);

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
		plugin->hub.command_del(plugin, pdata->command_patternexadd_handle);
		plugin->hub.command_del(plugin, pdata->command_patternexdel_handle);
		plugin->hub.command_del(plugin, pdata->command_patternexlist_handle);
		hub_free(pdata->command_patternadd_handle);
		hub_free(pdata->command_patterndel_handle);
		hub_free(pdata->command_patternlist_handle);		
		hub_free(pdata->command_patternexadd_handle);
		hub_free(pdata->command_patternexdel_handle);
		hub_free(pdata->command_patternexlist_handle);
		sqlite3_close(pdata->db);
	}
    
	hub_free(pdata);
	return 0;
}
