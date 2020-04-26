#ifndef CHIRC_HANDLERS_H
#define CHIRC_HANDLERS_H

#include "connection.h"
#include "constants.h"
#include "reply.h"
#include "server.h"
#include <pthread.h>

/* Define index number of command in dispatch table *
 * used so we can call cmd_id >= REGISTRATION_NEEDED to manage pre-registration
 * behavior. Every command at index 2 or later needs registration.
 */
#define INVALID -1
#define NICK 0
#define USER 1
#define REGISTRATION_NEEDED 4

/* Arguments to feed handler functions */
typedef struct handle {
    server_ctx *ctx;
    char *prefix;               // Prefix string of command, if available
    int cmd_id;                 // Maps to entry in dispatch table
    char* params[MAX_PARAMS];   // Parameters to the command
    conn* conn;                 // Sender of command
    char* server_hostname;      // To identify the host server
} handle;


/* 
 * Broadcasts a message to users or servers
 *
 * PREFIX (origin_conn's info) = :<nickname>!<username>@<hostname> 
 *                               if prefixmode = 0 (origin_conn is user)
 * 
 *                               :<nickname> 
 *                               if prefixmode = 1 (origin_conn is user)
 * 
 *                               :<servername> 
 *                               if prefixmode = 2 (origin_conn is user/server)
 *      
 * If origin_conn is NULL, then the message has no <prefix> in it
 * 
 * If nick_or_ch isn't NULL, fmt = "<prefix> <CMD> <nick_or_ch> <long_param>"; 
 * If nick_or_ch is NULL,    fmt = "<prefix> <CMD> <long_param>"
 * 
 * nick_or_ch - name of nick/channel in the message. Can be any string
 * CMD - name of command, etc NICK
 * origin_conn - connection doing the broadcasting
 * dest_conn - destination connection to send message to
 * colon_flag - whether to include a colon in before long param
 * prefix_mode - specifies the format of the prefix
 * relay_prefix - If non-NULL, replaces any regular prefix with this
 * 
 * Returns: -1 on failure, 0 on success
 */
int broadcast_gen(char* nick_or_ch, char* long_param, const char* CMD,
                conn* origin_conn, conn* dest_conn, 
                bool colon_flag, int prefix_mode, char *relay_prefix);


/* 
 * Same as broadcast_gen but assumes relay_prefix = NULL so a prefix
 * will always be generated based on prefix_mode
 */
int broadcast(char* nick_or_ch, 
                char* long_param, 
                const char* CMD, 
                conn* origin_conn, 
                conn* dest_conn, 
                bool colon_flag,
                int prefix_mode);



/* 
 * Broadcasts a message to a server
 *
 * PREFIX (origin_conn's info) = :<servername>
 * 
 * If origin_conn is not NULL fmt = "<prefix> <CMD> <long_param>"; 
 * If origin_conn is NULL,    fmt = "<CMD> <long_param>";
 * 
 * CMD - name of command, etc NICK
 * origin_conn - connection doing the broadcasting
 * dest_conn - destination connection to send message to
 * long_param - long parameter appendex to message
 * 
 * Returns: -1 on failure, 0 on success
 */
int broadcast_server(conn* origin_conn,
                     conn* dest_conn,
                     const char* CMD,
                     char* long_param);


/* 
 * Parses tokens to construct handle and then calls the corresponding
 * function in the dispatch table to execute the command
 *
 * tokens: list of tokens to iterate over
 * len: amount of tokens
 * conn: user sending the message
 * ctx: global server context
 *
 * Returns: -1 if error occurs.
 */
int handle_tokens(char** tokens, int len, conn* conn, server_ctx *ctx);


/* 
 * Checks if a user is in the hashtable users; if not, add them
 *
 * users: a double pointer because uthash requires
          this when passing the hash pointer into a function
          because it alters the hash pointer itself (see uthash docs)
 * 
 * Returns: 0 on success, -1 on failure
 */
int add_user(conn **users, conn *new_user);


/* 
 * Prints all users at the DEBUG level 
 *
 * users: a connection struct with UTHASH_HH handle to iterate with
 * 
 * Returns: nothing.
 */
void print_users(conn *users);


/* 
 * Increments connections count and adds user to hashtable
 * 
 * args: arguments to be passed on to fill in user struct.
 * 
 * user_info: Used when a user is registered via a relay command; args contains
 * the server connection that sent the relayed message and user_info contains 
 * info of the user to be registered. Set this to NULL for 
 * a normal client registrations
 * 
 * NOTE: Does not lock any of the structs for deadlock reasons. 
 * You must handle locking outside in the calling function
 *
 * Returns: 0 upon success, -1 upon failure.
 */
int register_user(handle *args, conn *new_user);


/* 
 * Finds user's connection struct by given nickname
 * 
 * ctx: global server context to access hashtable with all users
 * nickname: nickname of user
 *
 * Returns: a connection pointer of found user, NULL if not found.
 */
conn* find_user_by_nick(server_ctx *ctx, char *nickname);

/* 
 * Finds server from list of servers using servername as criteria
 *
 * servers: linked list of server handles
 * servername: servername to search fro
 *
 * Returns: found server handle if successful, NULL if not
 */
conn_hh* find_server(conn_hh* servers, char* servername);


/*
 * Relays the message(s) in rt_args to connected servers and/or clients
 * <prefix> <CMD> <short_param> :<long_param>
 * rt_args fields:
 *  conn *msg_origin;     // Connection which sent command. NULL -> no prefix
    char *CMD             // Command
    char *short_param;
    char *long_param;     // Message to relay out to other servers
    bool exclude_sender;  // If true, doesn't relay to msg_origin
    bool relay_users;     // Relay msg to users connected to server
    bool relay_servers;   // Relay msg to connected servers 
    bool no_prefix;       // If true, then do not include prefix in message

 * server_ctx is server context variable
 * A NULL value for server_msg or user_msg causes no message to be relayed
 * to the users or servers
 * Returns: 0 on success, -1 on failure.
 */
int relay_message(relay_args *rt_args, server_ctx *ctx);

/* Sets every field in rt_args to either 0 or NULL. Memset potentially 
 * had bugs, which is the purpose of this function which may be useless
 * TODO: investigate whether or not this is useless */
void reset_relay_args(relay_args *rt_args);

#endif
