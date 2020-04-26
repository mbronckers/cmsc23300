#ifndef CHIRC_HANDLERS_C
#define CHIRC_HANDLERS_C

#include "handlers.h"
#include "server.h"
#include "channel.h"
#include "message.h"
#include "connection.h"

/* General helper functions */

/*
 * Scans params and determines if there are at least num_params present
 *
 * params - pointer to the parameter strings
 * num_params - number of parameters to satisfy
 *
 * Returns true if there are at least num_params params in params
 */
bool enough_params(char **params, int num_params);


/*
 * Checks if nickname availabe by checking all users in global ctx variable
 *
 * args - allows for access to ctx to access hashtable with all users
 * nickname - nickname to test for
 * 
 * Returns true if nick available, false if not 
 */
bool nickname_available(handle *args, char *nickname);


/*
 * Counts the number of global IRC operators by iterating over users
 * by counting irc_operator flags
 * 
 * args - allows for access to ctx to access hashtable with all users
 *
 * Returns: count of IRC operators.
 */
int count_irc_ops(handle *args);


/* 
 * Helper function that executes PRIVMSG and NOTICE
 * 
 * args - handle that contains necessary information for command like params
 * 
 * send_replies - flag for MSG type
 *    true corresponds to PRIVMSG
 *    false corresponds to NOTICE
 * 
 * Returns 0 on success, -1 on failure
 */
int msg_helper(handle *args, bool send_replies);


/*
 * Helper function to find_server to compare a server handle against servername
 *
 * server - server handle from the linked list find_server iterates over
 */
conn_hh* cmp_server(conn_hh* server, char* servername);


/*
 * Helper function deal with PASS & SERVER commands. Verifies both password and
 * servername and sets appriopriate fields & sends responses
 * 
 * This function sets password in args->conn->password to the host password,
 * but this is fine since args->conn->password is not needed anymore after
 * registration
 * 
 * reply_flag - whether or not to send a reply back to the other server
 * 
 * Returns: 0 upon success, -1 upon failure.
 */
int verify_server(handle* args, bool reply_flag);


/* 
 * Handler functions - handle the corresponding command in their names
 * 
 * args - handle that contains neccessary info to execute command
 *        message string has been parsed into prefix & tokens already
 * 
 * Returns: -1 on an error and 0 on success. 
 * cmd_quit is an exception; it returns QUIT_SIGNAL = -5 on quit 
 */
int cmd_nick(handle* args);
int cmd_user(handle* args);
int cmd_quit(handle *args);
int cmd_privmsg(handle *args);
int cmd_notice(handle *args);
int cmd_lusers(handle *args);
int cmd_oper(handle *args);
int cmd_ping(handle *args);
int cmd_pong(handle *args);
int cmd_whois(handle *args); 
int cmd_join(handle *args);
int cmd_part(handle *args);
int cmd_list(handle *args);
int cmd_mode(handle *args);
int cmd_pass(handle *args);
int cmd_server(handle *args);
int cmd_connect(handle *args);

typedef int (*handler_function)(handle* args);

/* Entry for dispatch table struct*/
typedef struct handler_entry {
    char *name;
    handler_function func;
} handler_entry;

/* Dispatch table containing all handler functions */
/* NICK, USER, PASS, SERVER must be the first four elements in this table 
   due to status restrictions of other commands */
handler_entry handlers[] = {
                            {"NICK", cmd_nick},
                            {"USER", cmd_user},
                            {"PASS", cmd_pass},
                            {"SERVER", cmd_server},
                            {"QUIT", cmd_quit},
                            {"PRIVMSG", cmd_privmsg},
                            {"NOTICE", cmd_notice},
                            {"LUSERS", cmd_lusers},
                            {"OPER", cmd_oper}, 
                            {"PING", cmd_ping}, 
                            {"PONG", cmd_pong},
                            {"WHOIS", cmd_whois},
                            {"JOIN", cmd_join},
                            {"PART", cmd_part},
                            {"LIST", cmd_list},
                            {"MODE", cmd_mode},
                            {"CONNECT", cmd_connect}
                            };

int num_handlers = sizeof(handlers) / sizeof(struct handler_entry);

/* See handlers.h */
int handle_tokens(char** tokens, int len, conn* conn, server_ctx *ctx) {
    /* Args setup */
    handle* args = (handle*) calloc(1, sizeof(handle));
    char* hostname = (char*) calloc(MAX_MSG_LEN, sizeof(char));
    gethostname(hostname, MAX_MSG_LEN);

    args->prefix = NULL; 
    args->conn = conn;
    args->cmd_id = INVALID;
    args->server_hostname = strdup(hostname);
    args->ctx = ctx;

    /* Check for prefix first; if none, then first token is command */
    int first_param_idx = 1;
    if (tokens[0] == NULL) {
        chilog(ERROR, "First token is NULL!\n");
        return -1;
    } else if (tokens[0][0] == ':') {
        args->prefix = strdup(tokens[0]+1);
        first_param_idx = 2;
    }

    /* Set command id */
    for (int i = 0; i < num_handlers; i++) {
        if (strcmp(tokens[first_param_idx - 1], handlers[i].name) == 0) {
            args->cmd_id = i;
        }
    }
    
    if (len > MAX_PARAMS+1) {
        chilog(ERROR, "Too many parameters given");
        return -1;
    }

    /* Set parameters in args handle */
    for (int i = first_param_idx; i < len; i++) {
        args->params[i-first_param_idx] = strdup(tokens[i]);
    }
    chilog(TRACE, "Handler parameters successfully set");


    /* Some error checking */
    if (args->cmd_id == INVALID) {
        if (args->conn->status < REGISTERED) {
            return 0;  // Nothing is done, silently ignore message
        }
        else {  // after registration is done:
            chilog(ERROR, "Command invalid");
            reply(args, ERR_UNKNOWNCOMMAND, "%s :Unknown command", 
                tokens[first_param_idx - 1]);
            return -1;
        }
   
    } else {
        /* Command needs registration - check if  */
        if (args->cmd_id >= REGISTRATION_NEEDED 
                && args->conn->status != REGISTERED
                && args->conn->status != SERVER_CONNECTED) {
            reply(args, ERR_NOTREGISTERED, ":You have not registered", NULL);
            return -1;
        }
        
        /* Call handler function */
        chilog(TRACE, 
               "Executing \"%s\" with params <%s> <%s> <%s> <%s>, prefix <%s>",
                handlers[args->cmd_id].name, args->params[0], args->params[1],
                args->params[2], args->params[3], args->prefix);
        
        return handlers[args->cmd_id].func(args);
    }

    /* Clean up memory */
    free(hostname);
    if (args->server_hostname) free(args->server_hostname);
    if (args->prefix) free(args->prefix);
    free(args);
    
    return 0;
}


/* See handlers.h */
int broadcast(char* nick_or_ch, char* long_param, const char* CMD,
                conn* origin_conn, conn* dest_conn, 
                bool colon_flag, int prefix_mode) {
    broadcast_gen(nick_or_ch, long_param, CMD, origin_conn, dest_conn,
                    colon_flag, prefix_mode, NULL);
}

/* TODO: explain that relay_prefix overrides the regular prefix */
int broadcast_gen(char* nick_or_ch, char* long_param, const char* CMD,
                conn* origin_conn, conn* dest_conn, 
                bool colon_flag, int prefix_mode, char *relay_prefix) {
    char buf[MAX_MSG_LEN];
    const char* fmt;

    /* Create prefix of relay message depending on prefix mode */
    char prefix[MAX_MSG_LEN]; 
    if (origin_conn != NULL) {
        if (!relay_prefix) {  // Automatically generate prefix 
                              // based on user/server and prefix_mode
            if (origin_conn->user_flag) {
                if (prefix_mode == 0) {
                    sprintf(prefix, ":%s!%s@%s", 
                        origin_conn->nickname,
                        origin_conn->username,
                        origin_conn->hostname); 
                } else if (prefix_mode == 1) {  // prefix is :nickname
                    sprintf(prefix, ":%s", origin_conn->nickname);    
                } else if (prefix_mode == 2) {  // prefix is :servername
                    sprintf(prefix, ":%s", origin_conn->servername);    
                } else {  // invalid prefix_mode then
                    chilog(ERROR, "Invalid prefix type %d called for %s", 
                            prefix_mode, CMD);
                    return -1;
                }
            } else {  // Incoming message is from server
                sprintf(prefix, ":%s", 
                    origin_conn->servername);
            } 
        } else {  // Use relayed prefix
            sprintf(prefix, ":%s", relay_prefix);
            chilog(DEBUG, "Used relay prefix %s", prefix);
        }  
    }         
    
    /* Specify string format according to given parameters */
    if (origin_conn == NULL) {  // No prefix in this case
        if (nick_or_ch) {
            if (long_param) {
                if (colon_flag) {
                    fmt = "%s %s :%s\r\n"; 
                } else {
                    fmt = "%s %s %s\r\n";
                }
                sprintf(buf, fmt, CMD, nick_or_ch, long_param);
            } else {
                fmt = "%s %s\r\n";
                sprintf(buf, fmt, CMD, nick_or_ch);
            }
        } else {
            if (long_param) {
                fmt = "%s :%s\r\n";      
                sprintf(buf, fmt, CMD, long_param);
            } else {
                fmt = "%s %s\r\n";
                sprintf(buf, fmt, CMD);
            }
        }
    } else {  // there is a prefix
        if (nick_or_ch) {
            if (long_param) {
                if (colon_flag) {
                    fmt = "%s %s %s :%s\r\n"; 
                } else {
                    fmt = "%s %s %s %s\r\n";
                }
                sprintf(buf, fmt, prefix, CMD, nick_or_ch, long_param);
            } else {
                fmt = "%s %s %s\r\n";
                sprintf(buf, fmt, prefix, CMD, nick_or_ch);
            }
        } else {
            if (long_param) {
                fmt = "%s %s :%s\r\n";      
                sprintf(buf, fmt, prefix, CMD, long_param);
            } else {
                fmt = "%s %s\r\n";
                sprintf(buf, fmt, prefix, CMD);
            }
        }    
    }
    
    chilog(TRACE, "Broadcasting: %s", buf);
    if(dest_conn->user_flag) {
        chilog(TRACE, "Broadcast dest: %s", dest_conn->username);
    } else {
        chilog(TRACE, "Broadcast dest: %s", dest_conn->servername);
    }
    
    /* Send message in buffer to socket*/
    int bytes = strlen(buf);
    pthread_mutex_lock(&dest_conn->conn_lock);
    if (send_all(dest_conn->conn_socket, buf, &bytes) == -1) {
        chilog(ERROR, "Socket send_all failed, socket %s message %s", 
                    dest_conn->conn_socket, buf);
        pthread_mutex_unlock(&dest_conn->conn_lock);
        return -1;
    }
    pthread_mutex_unlock(&dest_conn->conn_lock);

    return 0;
}

/* See above function declaration */
int broadcast_server(conn* origin_conn, conn* dest_conn,
                        const char* CMD, char* long_param) {
    char buf[MAX_MSG_LEN];
    const char* fmt;

    /* Create prefix of message */
    char prefix[MAX_MSG_LEN];
    if (origin_conn != NULL) {
        sprintf(prefix, ":%s", origin_conn->servername);            
    }
    
    /* Specify string format according to given parameters */
    if (origin_conn != NULL) {
        if (long_param) {
            fmt = "%s %s %s\r\n";
            sprintf(buf, fmt, prefix, CMD, long_param);
        } else {
            fmt = "%s %s\r\n";
            sprintf(buf, fmt, prefix, CMD);
        }
    } else {
        if (long_param) {
            fmt = "%s %s\r\n";
            sprintf(buf, fmt, CMD, long_param);
        }    
    }
    
    chilog(TRACE, "Broadcasting: %s", buf);
    
    /* Send message in buffer to socket*/
    int bytes = strlen(buf);
    pthread_mutex_lock(&dest_conn->conn_lock);
    if (send_all(dest_conn->conn_socket, buf, &bytes) == -1) {
        chilog(ERROR, "Socket send_all failed to socket <%i> message <%s>",
                        dest_conn->conn_socket, buf);
        pthread_mutex_unlock(&dest_conn->conn_lock);
        return -1;
    }
    pthread_mutex_unlock(&dest_conn->conn_lock);

    return 0;
}

/* ------- Handler functions -------- 
 * These execute the corresponding command in the IRC protocol 
 * They return 0 on success and -1 on failure
 * with the exception of cmd_quit; it returns QUIT_MSG on success
 */


int cmd_pass(handle *args) {
    conn_status status = args->conn->status;
    chilog(CRITICAL, "BARNEY STATUS %d", status);
    /* Whether or not to send replies upon successful server registration */
    /* Used to prevent infinite relay chain */
    bool reply_flag = true;  
    if (!enough_params(args->params, 3)) {
        chilog(ERROR, "More parameters needed");
        reply(args, ERR_NEEDMOREPARAMS, "%s :Not enough parameters", 
            handlers[args->cmd_id].name);
        return -1;
    }

    /* Detecting CONNECT triggered responses => no reply needed */
    if (args->prefix != NULL) {
        reply_flag = false; 
    }

    /* Act according to status*/
    if (status == NOT_REGISTERED) {
        conn* new_server = args->conn;

        /* Set to server connection*/
        new_server->user_flag = false;  

        /* Verify password after SERVER is received */
        new_server->password = strdup(args->params[0]);

        /* Update connection status */
        new_server->status = PASS_GIVEN;
        chilog(TRACE, "Status of <%s> set to PASS_GIVEN <%i>", 
                new_server->hostname, new_server->status);

    } else if (status == SERVER_GIVEN) {
        /* Verify password after SERVER is received 
         * mangles args->conn->password temporarily; sets it to the current 
         * server's password (or whatever was sent). This is fine though
         * because verify_server will set the other server's password to the
         * correct one and it is never used again */

        args->conn->password = strdup(args->params[0]);

        return verify_server(args, reply_flag);

    } else if (status == PASS_GIVEN) { 
        // what to do if password was already given (but no servername)
        char* password = args->conn->password;
        password = strdup(args->params[0]);
        chilog(TRACE, "Password set to <%s>", password);

    }  else if (status == SERVER_CONNECTED) {
        chilog(ERROR, "Connection already registered");
        char long_param[MAX_MSG_LEN];
        sprintf(long_param, "%s :Connection already registered",
                 args->conn->servername);
        broadcast_server(args->ctx->whoami, args->conn, 
                        ERR_ALREADYREGISTRED, long_param);

    } 

    return 0;

}


/* See function declaration above */
int verify_server(handle* args, bool reply_flag) {
    /* Verify server allowed & not present already */
    char* servername = args->conn->servername;

    chilog(TRACE, "Servername looking for <%s>", servername);

    pthread_mutex_lock(&args->ctx->servers_lock);
    conn_hh* allowed_server = find_server(args->ctx->allowed_servers,
                                                             servername); 

    conn_hh* connected_server = find_server(args->ctx->connected_servers,
                                                             servername);
    pthread_mutex_unlock(&args->ctx->servers_lock);

    if (allowed_server == NULL) {
        chilog(TRACE, "Servername <%s> not allowed", servername);

        /* Send apprioprate error */
        broadcast(NULL, "Server not configured here",
                        "ERROR", NULL, args->conn, true, 0);

        return 0;

    } else if (connected_server != NULL) {
        chilog(TRACE, "Servername <%s> already present", servername);
        
        /* Send appropriate error*/
        char long_param[MAX_MSG_LEN];
        const char* fmt = "ID \"%s\" already registered";
        sprintf(long_param, fmt, servername);
        broadcast(NULL, long_param, "ERROR", NULL, args->conn, true, 0);
        
        return 0;
    } 

    chilog(TRACE, "Servername <%s> valid" , servername);

    /* Actual password; password of my server */
    char* my_pass = args->ctx->whoami->password;

    /* Password verification */
    if (strcmp(args->conn->password, my_pass) == 0) {
        chilog(TRACE, "Password <%s> correct for my server", my_pass);

        /* Setting up new server conn. Correct the password and servername */
        conn* other_server = args->conn;
        conn_hh* other_server_info = find_server(args->ctx->allowed_servers, 
                                 other_server->servername);

        /* Restore fields to what they should be */
        char* actual_password = strdup(other_server_info->conn->password);
        char* actual_servername = strdup(other_server_info->conn->servername);

        other_server->password = actual_password;
        other_server->servername = actual_servername;
        other_server->user_flag = false;  
        other_server->status = SERVER_CONNECTED;

        /* Add server to list of connected servers (to host) */
        conn_hh* new_server_hh = (conn_hh*) calloc(1, sizeof(conn_hh));
        new_server_hh->conn = other_server; 
        
        pthread_mutex_lock(&args->ctx->servers_lock);
        chilog(DEBUG, "Adding server <%s> to server list", 
                                    args->conn->servername);
        LL_APPEND(args->ctx->connected_servers, new_server_hh);

        pthread_mutex_lock(&args->ctx->users_lock);
        args->ctx->num_known += 1;
        pthread_mutex_unlock(&args->ctx->users_lock);
        pthread_mutex_unlock(&args->ctx->servers_lock);

        if (reply_flag == false) {
            return 0;
        }

        /* Constructing replies */
        char buf[MAX_MSG_LEN];
        char* temp_active_passwd = strdup(actual_password);
        char* pass_long_param = "0210 chirc|3.11";
        sprintf(buf, "%s %s", temp_active_passwd, pass_long_param);
        broadcast_server(args->ctx->whoami, args->conn,
                        "PASS", buf);

        char buf2[MAX_MSG_LEN];
        char* token = "1";  // Specified in the instructions
        char* serverinfo = ":chirc server";  // arbitrary string per instructs
        char* active_server_name = strdup(args->ctx->whoami->servername);
        sprintf(buf2, "%s %s %s", active_server_name, token, serverinfo);
        broadcast_server(args->ctx->whoami, args->conn,
                        "SERVER", buf2);
        return 0;

    } else {
        /* Send wrong password error*/
        chilog(TRACE, "Password <%s> incorrect", args->conn->password);
        broadcast(NULL, "Bad password", "ERROR", NULL, args->conn, true, 0);
        return -1;
    } 
}


int cmd_server(handle *args) {
    /* Whether or not to send replies upon successful server registration */
    /* Used to prevent infinite relay chain */
    bool reply_flag = true;  
    /* Count parameters*/
    if (!enough_params(args->params, 2)) {
        chilog(ERROR, "More parameters needed");
        reply(args, ERR_NEEDMOREPARAMS, "%s :Not enough parameters", 
            handlers[args->cmd_id].name);
        return -1;
    }
    
    conn_status status = args->conn->status;

    /* Detecting CONNECT triggered responses => no reply needed */
    if (args->prefix != NULL) {
        reply_flag = false;
    }

    if (status == NOT_REGISTERED) {
        conn* new_server = args->conn;
        /* Set to server connection*/
        new_server->user_flag = false;  
        new_server->servername = strdup(args->params[0]);
        new_server->status = SERVER_GIVEN;
        
        chilog(TRACE, "Status of <%s> set to SERVER_GIVEN <%i>", 
                new_server->hostname, new_server->status);

        chilog(TRACE, "Set servername to <%s>", args->conn->servername);

    } else if (status == PASS_GIVEN) {
        /* Contains our servername at this point; this is a placeholder
         * conn->servername will get changed back to the other servername
         * in the network_file in verify_server */
        args->conn->servername = strdup(args->params[0]);

        /* Verify server and send back appropriate response */
        return verify_server(args, reply_flag);

    } else if (status == SERVER_GIVEN) {
        /* Changing server name but not conn yet */
        conn* new_server = args->conn;

        /* Set servername */
        new_server->servername = strdup(args->params[0]);

    } else if (status == SERVER_CONNECTED) {
        chilog(ERROR, "Connection already registered");
        char long_param[MAX_MSG_LEN];
        sprintf(long_param, "%s :Connection already registered",
                 args->conn->servername);
        broadcast_server(args->ctx->whoami, args->conn, ERR_ALREADYREGISTRED,
                         long_param);

    } 

    return 0;
}


int cmd_connect(handle *args) {
    if (!args->conn->user_flag || !args->conn->is_operator) {
        chilog(ERROR, "CONNECT: not a user or user is not operator");
        reply(args, ERR_NOPRIVILEGES, 
                ":Permission Denied- You're not an IRC operator");
        return -1;
    }

    if (!enough_params(args->params, 2)) {
        chilog(ERROR, "More parameters needed: CONNECT");
        reply(args, ERR_NEEDMOREPARAMS, "%s :Not enough parameters", 
            handlers[args->cmd_id].name);
        return -1;
    }

    /* Ignore port as instructions say; port is in the allowed_servers list */
    pthread_mutex_lock(&args->ctx->servers_lock);
    char *servername = args->params[0];
    conn_hh *server = find_server(args->ctx->allowed_servers, servername);

    if (server == NULL) {
        chilog(ERROR, "CONNECT target server failed");
        reply(args, ERR_NOSUCHSERVER, "%s :No such server", servername);
        pthread_mutex_unlock(&args->ctx->servers_lock);
        return -1;
    }
    pthread_mutex_unlock(&args->ctx->servers_lock);

    char *port = strdup(server->conn->port);

    /* Create new connection to be sent to service_client */
    conn* new_server = connection_new(false);
    new_server->port = port;

    /* connect_to_server spawns the worker thread handling the server. */
    if (connect_to_server(servername, server->conn->port, 
                          args->ctx, new_server) == -1) {
        
        chilog(ERROR, "Could not connect to server %s on port %s", 
                    servername, server->conn->port);
        
        return -1;  // IRC spec does not specify any error reply; return silent
    } else {
        chilog(DEBUG, "CONNECT to server %s on port %s success", 
            servername, server->conn->port);
    }

    free(port);
}


int cmd_part(handle *args) {
    if (args->params[0] == NULL) {
        chilog(ERROR, "More parameters needed: PART");
        reply(args, ERR_NEEDMOREPARAMS, "%s :Not enough parameters", 
            handlers[args->cmd_id].name);
        return -1;
    }

    conn* user = args->conn;
    char* nick_or_ch = args->params[0];
    char* parting_msg = args->params[1];    
    chan* p;  // Pointer to channel to part

    /* Find channel */
    if ((p = channel_find(args->ctx, nick_or_ch)) == NULL) {
        chilog(ERROR, "Channel <%s> does not exist", nick_or_ch);
        reply(args, ERR_NOSUCHCHANNEL, "%s :No such channel", 
            nick_or_ch);
        return 0;
    }

    /* Find user in channel, remove them */
    if (remove_user_from_channel(args->ctx, p, user) < 0) {;
        chilog(ERROR, "User <%s> not part of channel <%s>", 
            user->username, nick_or_ch);
        reply(args, ERR_NOTONCHANNEL, "%s :You're not on that channel", 
            nick_or_ch);
        return 0;
    }

    /* Send reply to parted user */
    chilog(TRACE, "Sending reply PART...");
    broadcast(p->name, parting_msg, "PART", user, user, true, 0);

    /* Send broadcast to everyone else */
    chilog(TRACE, "Sending broadcast PART...");
    pthread_mutex_lock(&p->chan_lock);
    chilog(TRACE, "Channel lock set");
    conn_hh* t;
    LL_FOREACH(p->users, t) broadcast(p->name, parting_msg, "PART",
                                        user, t->conn, true, 0);
    pthread_mutex_unlock(&p->chan_lock);
    
    chilog(TRACE, "Channel lock removed");
    return 0;
}


int cmd_join(handle *args) {
    if (args->params[0] != NULL) {
        chan* joined_channel; // Pointer to channel to join
        char* name = args->params[0];
        conn* user;  // Could also be a server: TODO: change name

        if (args->conn->user_flag) {
            user = args->conn;
        } 

        /* Received a relay JOIN */
        else {  
            /* args->prefix contains <:nick> */
            if (!args->prefix) {        
                chilog(ERROR, "No :nick prefix given for relayed JOIN");
                return -1;
            }
            
            pthread_mutex_lock(&args->ctx->users_lock);
            user = find_user_by_nick(args->ctx, args->prefix);
            pthread_mutex_unlock(&args->ctx->users_lock);
            
            if (!user) {
                chilog(ERROR, "Could not find user w nick <%s>", args->prefix);
                return -1;
            }
        }

        bool new_channel = true;    // If new channel, user is channel op
        pthread_mutex_lock(&args->ctx->channels_lock);
        
        /* Find or create channel */
        if ((joined_channel = channel_find(args->ctx, name)) != NULL) {
            chilog(TRACE, "Found channel <%s>", name);
            new_channel = false;
        }
        else if ((joined_channel = channel_create(args->ctx, name)) == NULL) {
            chilog(ERROR, "Could not create channel");
        } else {
            chilog(DEBUG, "Created channel <%s>", name);
        }
        pthread_mutex_unlock(&args->ctx->channels_lock);

        /* Add user to channel; if present return */
        conn_hh* up = channel_find_user(joined_channel, user->username);
        if (up != NULL) {
            chilog(ERROR, "User <%s> is already in channel", user->username);
            return -1;
        } else if ((up = channel_add_user(joined_channel, user)) == NULL) {
            chilog(ERROR, "Could not add user <%s> to channel <%s>",
             user->username, name);
            return -1;
        }
        
        chilog(INFO, "User <%s> joined channel <%s>", user->username, name);

        /* Log channel info */
        channel_show(joined_channel);

        /* Set user as channel op iff it is a new channel */
        if (new_channel && (channel_set_op(joined_channel, up, true) != 0)) { 
            chilog(TRACE, "Could not set user <%s> as channel operator",
                 user->username);
        }

        /* Sending broadcast & reply */
        chilog(TRACE, "Sending broadcast JOIN...");
        
        pthread_mutex_lock(&joined_channel->chan_lock);

        conn_hh* other_user;
        LL_FOREACH(joined_channel->users, other_user) {
            /* Only send if user is on my server */
            if (strcmp(other_user->conn->servername, 
                args->ctx->whoami->servername) == 0) {
                broadcast_gen(joined_channel->name, NULL, "JOIN",
                    user, other_user->conn, false, 0, args->prefix);
            }
        }
        pthread_mutex_unlock(&joined_channel->chan_lock);

        char* msg = channel_get_nicks(args->ctx, joined_channel);
        if (args->conn->user_flag) {
            reply(args, RPL_NAMREPLY, "= %s %s", joined_channel->name, msg);
            reply(args, RPL_ENDOFNAMES, "%s :End of NAMES list", 
                    joined_channel->name);
        }

        /* Relay JOIN to all other servers */
        pthread_mutex_lock(&args->ctx->rt_lock);
        args->ctx->rt_args->msg_origin = args->conn;
        args->ctx->rt_args->CMD = strdup("JOIN");
        /* We do not want a colon before the #channelname in relayed msg */
        args->ctx->rt_args->short_param = strdup(joined_channel->name);
        args->ctx->rt_args->exclude_sender = true;
        args->ctx->rt_args->relay_servers = true;
        if(args->prefix) {  // Keep relaying this message
            args->ctx->rt_args->prefix = strdup(args->prefix);
        } else {
            args->ctx->rt_args->prefix = strdup(up->conn->nickname);
        }
        pthread_cond_signal(&args->ctx->rt_cv);  
        pthread_mutex_unlock(&args->ctx->rt_lock);

    } else {
        chilog(ERROR, "More parameters needed");
        reply(args, ERR_NEEDMOREPARAMS, "%s :Not enough parameters", 
            handlers[args->cmd_id].name);
        return -1;
    }

    return 0;
}


int cmd_nick(handle *args) {
    /* Process server relays of NICK message */
    /* Register the corresponding user via the relay form of register_user */
    /* PARAMS: NICK <nickname> <hopcount> <username> <host> <servertoken>
               <umode> <realname> */
    if (args->conn->user_flag == false) {
        chilog(TRACE, "SERVER nick command received");
        if (!enough_params(args->params, 7)) {
            chilog(ERROR, "Not enough params (<7) in server version of nick");
            return -1;
        }
        char *nick = args->params[0];
        char *username = args->params[2];
        char *realname = args->params[6];
        char *hostname = args->params[3];
        char *servername = args->prefix;  // user could be multiple hops away
        conn *new_user = connection_new(true);
        new_user->nickname = strdup(nick);
        new_user->username = strdup(username);
        new_user->hostname = strdup(hostname);
        new_user->realname = strdup(realname);
        new_user->servername = strdup(servername);
        new_user->status = REGISTERED;

        pthread_mutex_lock(&args->ctx->users_lock);
        pthread_mutex_lock(&args->ctx->servers_lock);
        register_user(args, new_user);
        pthread_mutex_unlock(&args->ctx->servers_lock);
        pthread_mutex_unlock(&args->ctx->users_lock);

        return 0;
    }
    char *old_nick = NULL;  // stores old nickname for relay message
    char *new_nick = args->params[0];
    if (new_nick != NULL) {
        
        /* Determine if new nickname avaiable, save the old nickname if so */
        pthread_mutex_lock(&args->ctx->users_lock);
        bool available = nickname_available(args, new_nick);
        if (args->conn->nickname) old_nick = strdup(args->conn->nickname);
        pthread_mutex_unlock(&args->ctx->users_lock);

        if (available) {
            /* Set known if previously unknown */
            pthread_mutex_lock(&args->ctx->users_lock);
            pthread_mutex_lock(&args->ctx->servers_lock);
            if (args->conn->nickname == NULL && args->conn->username == NULL) {
                args->ctx->num_known += 1;
                args->ctx->local_clients += 1;
            }
            pthread_mutex_unlock(&args->ctx->servers_lock);
            pthread_mutex_unlock(&args->ctx->users_lock);

            /* If known registered user, relay nick change to channels */
            if (connection_is_registered(args->conn) 
                && args->conn->status == REGISTERED) {
                
                /* Relaying NICK change to all channels user is in */
                chan* temp_chan = NULL;
                pthread_mutex_lock(&args->ctx->channels_lock);
                LL_FOREACH(args->ctx->channels, temp_chan) {
                    if (channel_find_user(temp_chan, args->conn->username)) {
                        conn_hh* t;
                        LL_FOREACH(temp_chan->users, t) {
                            broadcast(NULL, new_nick, "NICK",
                                        args->conn, t->conn, true, 0);
                        }
                    }
                }
                pthread_mutex_unlock(&args->ctx->channels_lock);

                /* TODO: relay name change to servers */
                pthread_mutex_lock(&args->ctx->rt_lock);
                args->ctx->rt_args->msg_origin = args->conn;
                args->ctx->rt_args->CMD = strdup("NICK");
                args->ctx->rt_args->long_param = strdup(new_nick);
                args->ctx->rt_args->exclude_sender = true;
                args->ctx->rt_args->relay_servers = true;
                pthread_cond_signal(&args->ctx->rt_cv);  
                pthread_mutex_unlock(&args->ctx->rt_lock);

                if (old_nick) free(old_nick);
            }

            /* Change nickname in user struct */            
            if (args->conn->nickname) free(args->conn->nickname);
            pthread_mutex_lock(&args->ctx->users_lock);
            args->conn->nickname = strdup(args->params[0]);
            pthread_mutex_unlock(&args->ctx->users_lock);
            
            /* If new user, send RPL_WELCOME */
            if (connection_is_registered(args->conn) 
                && args->conn->status != REGISTERED) {
                args->conn->status = REGISTERED;

                pthread_mutex_lock(&args->ctx->users_lock);
                register_user(args, NULL);
                pthread_mutex_unlock(&args->ctx->users_lock);
                print_users(args->ctx->users);
                
                chilog(TRACE, "About to send reply...");
                const char *VERSION = "3.14";
                const char *DATE = "12-22-1998";
                reply(args, RPL_WELCOME, 
                    ":Welcome to the Internet Relay Network %s!%s@%s",
                    args->conn->nickname, args->conn->username,
                    args->conn->hostname, NULL);
                reply(args, RPL_YOURHOST, 
                    ":Your host is %s, running version %s",
                    args->server_hostname, VERSION);
                reply(args, RPL_CREATED, 
                    ":This server was created %s", DATE);
                reply(args, RPL_MYINFO, 
                    "%s %s %s %s",
                    args->conn->hostname, VERSION, "ao", "mtov");
                cmd_lusers(args);
                reply(args, ERR_NOMOTD, 
                    ":MOTD File is missing");
            }

        } else {
            reply(args, ERR_NICKNAMEINUSE, "%s :Nickname is already in use", 
                args->params[0]);
            return -1;
        }

    } else {
        chilog(ERROR, "No nickname specified");
        reply(args, ERR_NONICKNAMEGIVEN, ":No nickname given");
        return -1;
    }
    
    return 0;    
}


/* See handlers.h */
conn *find_user_by_nick(server_ctx *ctx, char *nickname) {
    conn* target;
    for (target = ctx->users; target != NULL; target = target->hh.next) {
        if (strcmp(target->nickname, nickname) == 0) {
            break;
        }
    }
    return target;
}


/* See header above */
int msg_helper(handle *args, bool send_replies) {
    if (args->conn->user_flag == false) {
        chilog(DEBUG, "Parsing server privmsg/notice");
    }
    char *command;
    if (send_replies) {
        command = "PRIVMSG";
    } else {
        command = "NOTICE";
    }

    /* Target user's nickname and message to be sent */
    char *target_name = args->params[0];
    char *msg = args->params[1];

    if (target_name == NULL) { 
        if (send_replies) reply(args, ERR_NORECIPIENT, 
            ":No recipient given (%s)", handlers[args->cmd_id].name);
        return -1;
    } 
    if (msg == NULL) {
        if (send_replies) reply(args, ERR_NOTEXTTOSEND, ":No text to send");
        return -1;
    }

    /* Find the connection to send privmsg to */
    pthread_mutex_lock(&args->ctx->users_lock);
    chilog(INFO, "desired user to find: %s", target_name);
    conn *target_u = find_user_by_nick(args->ctx, target_name);
    pthread_mutex_unlock(&args->ctx->users_lock);      

    chilog(INFO, "User found by nick: %s", target_u);
    /* Now try to find target in channels list if target isn't a user */
    chan *target_chan = NULL;
    if (target_u == NULL) {
        pthread_mutex_lock(&args->ctx->channels_lock);
        target_chan = channel_find(args->ctx, target_name);
        pthread_mutex_unlock(&args->ctx->channels_lock);
        if (target_chan == NULL) {
            if (send_replies) reply(args, ERR_NOSUCHNICK,
                 "%s :No such nick/channel", target_name);
            return -1;
        }
    }

    char full_msg[MAX_MSG_LEN];

    /* Determining where to send message*/
    if (target_u) {     // Send message to a person
        
        /* User on my server; send privmsg directly to them */
        /* target->servername == NULL => they are not directly connected to us*/
        if (target_u->servername != NULL
            && args->ctx->whoami->servername != NULL 
            && strcmp(target_u->servername, 
                      args->ctx->whoami->servername) == 0) {
        
            /* Have to use broadcast_gen because when we send a relayed PRIVMSG
             * to a client, it should have the format
             * <origin_nickname> PRIVMSG <target_u> <msg> */
            return broadcast_gen(target_u->nickname, msg, 
                                 command, args->conn, target_u,
                                 true, 0, args->prefix);
        
        } else {       // User not on my server. Relay.
            pthread_mutex_lock(&args->ctx->rt_lock);
            args->ctx->rt_args->msg_origin = args->conn;
            args->ctx->rt_args->CMD = strdup(command);
            args->ctx->rt_args->short_param = strdup(target_u->nickname);
            args->ctx->rt_args->long_param = strdup(msg);
            args->ctx->rt_args->exclude_sender = true;
            args->ctx->rt_args->relay_servers = true;
            if (args->prefix) {
                args->ctx->rt_args->prefix = strdup(args->prefix);
            }  else {
                args->ctx->rt_args->prefix = strdup(args->conn->nickname);
            }
            pthread_cond_signal(&args->ctx->rt_cv);  
            pthread_mutex_unlock(&args->ctx->rt_lock);
        }

    } else {          // send message to a channel AND other servers
        
        /* If sender is a user, then check that user is in channel */
        if (args->conn->user_flag) {
            if (channel_find_user(target_chan, args->conn->username) == NULL) {
                if (send_replies) reply(args, ERR_CANNOTSENDTOCHAN,
                    "%s :Cannot send to channel", target_chan->name);
                return -1;
            }
        }
        
        /* Otherwise just relay w/o any security checks */
        conn_hh *user;
        pthread_mutex_lock(&target_chan->chan_lock);
        LL_FOREACH(target_chan->users, user) {
            if (user->conn == args->conn || strcmp(
                user->conn->servername, args->ctx->whoami->servername)!= 0) {
                continue; // no PRIVMSG to self, users not on server
            } else {
            broadcast_gen(target_name, msg, command, args->conn, 
                        user->conn, true, 0, args->prefix);
            }
        }
        pthread_mutex_unlock(&target_chan->chan_lock);

        pthread_mutex_lock(&args->ctx->rt_lock);
        args->ctx->rt_args->msg_origin = args->conn;

        args->ctx->rt_args->CMD = strdup(command);
        args->ctx->rt_args->short_param = strdup(target_name);
        args->ctx->rt_args->long_param = strdup(msg);
        args->ctx->rt_args->exclude_sender = true;
        args->ctx->rt_args->relay_servers = true;
        
        chilog(INFO, "Prefix: %s", args->prefix);
        
        if (args->prefix) {
            args->ctx->rt_args->prefix = strdup(args->prefix);
        }  else {
            if (!args->conn->user_flag) {
                chilog(ERROR, "server PRIVMSG needs prefix");
                return -1;
            }
            args->ctx->rt_args->prefix = strdup(args->conn->nickname);
        }
        pthread_cond_signal(&args->ctx->rt_cv);  
        pthread_mutex_unlock(&args->ctx->rt_lock);
    }
    return 0;
}


int cmd_privmsg(handle *args) {
    return msg_helper(args, true);
}


int cmd_notice(handle *args) {
    return msg_helper(args, false);
}


/* See above function declaration */
bool enough_params(char **params, int num_params) {
    for(int i = 0; i < num_params; i++) {
        if(params[i] == NULL) {
            return false;
        }
    }
    return true;
}


int cmd_user(handle *args) {
    /* Check if valid & not registered already */
    if (enough_params(args->params, 4)) {
        if (connection_is_registered(args->conn)) {
            reply(args, ERR_ALREADYREGISTRED, 
                    ":Unauthorized command (already registered)");
            return -1;
        }

        /* Now we know that connection is a user, so it is known */
        if (args->conn->nickname == NULL && args->conn->username == NULL) {
            args->ctx->num_known += 1;
            args->ctx->local_clients += 1;
        }
        args->conn->username = strdup(args->params[0]);
        args->conn->realname = strdup(args->params[3]);
    } else {
        chilog(ERROR, "More parameters needed");
        reply(args, ERR_NEEDMOREPARAMS,
                 "%s :Not enough parameters", handlers[args->cmd_id].name);
    }

    if (connection_is_registered(args->conn) 
        && args->conn->status != REGISTERED) {
        args->conn->status = REGISTERED;

        pthread_mutex_lock(&args->ctx->users_lock);
        register_user(args, NULL);
        pthread_mutex_unlock(&args->ctx->users_lock);
        print_users(args->ctx->users);

        chilog(TRACE, "About to send reply...");
        const char *VERSION = "3.14";
        const char *DATE = "12-22-1998";
        reply(args, RPL_WELCOME, 
            ":Welcome to the Internet Relay Network %s!%s@%s",
            args->conn->nickname, args->conn->username,
            args->conn->hostname, NULL);
        reply(args, RPL_YOURHOST, 
            ":Your host is %s, running version %s",
            args->server_hostname, VERSION);
        reply(args, RPL_CREATED, 
            ":This server was created %s", DATE);
        reply(args, RPL_MYINFO, 
            "%s %s %s %s",
            args->conn->hostname, VERSION, "ao", "mtov");
        cmd_lusers(args);
        reply(args, ERR_NOMOTD, 
            ":MOTD File is missing");
    }

    return 0;
}


int cmd_quit(handle *args) {
    char *message = "Client Quit";
    if (args->params[0] != NULL) {
        message = args->params[0];
        chilog(TRACE, "Message: %s", message);
    }

    /* Relay to channels */
    chan* temp_chan = NULL;
    pthread_mutex_lock(&args->ctx->channels_lock);
    LL_FOREACH(args->ctx->channels, temp_chan) {
        if (channel_find_user(temp_chan, args->conn->username)) {
            remove_user_from_channel(args->ctx, temp_chan, args->conn);
            conn_hh* t;
            LL_FOREACH(temp_chan->users, t) {
                broadcast(NULL, message, "QUIT", args->conn, t->conn, true, 0);
            }
        }
    }
    pthread_mutex_unlock(&args->ctx->channels_lock);

    /* Send to user*/ 
    char error_msg[MAX_MSG_LEN];
    sprintf(error_msg, "ERROR :Closing Link: %s (%s)\r\n", 
        args->conn->hostname, message);

    int bytes = strlen(error_msg);

    /* Lock for reading nick and sending data to all */
    pthread_mutex_lock(&args->conn->conn_lock);  //
    if (send_all(args->conn->conn_socket, error_msg, &bytes) < 0) {
        chilog(ERROR, "Socket send_all failed, socket %s message %s", 
                args->conn->conn_socket, error_msg);
        pthread_mutex_unlock(&args->conn->conn_lock); 
        return -1;
    }
    pthread_mutex_unlock(&args->conn->conn_lock);
    
    return QUIT_SIGNAL;
}


int cmd_lusers(handle *args) {
    pthread_mutex_lock(&args->ctx->users_lock);
    pthread_mutex_lock(&args->ctx->channels_lock);
    pthread_mutex_lock(&args->ctx->servers_lock);
    int total_registered = args->ctx->num_registered;

    /* Total number of OTHER known clients + servers */
    int total_known = args->ctx->num_known;  

    /* Total number of OTHER connections */
    int total_conns = args->ctx->num_connections;

    /* Number of users connected to ME */
    int num_my_users = args->ctx->local_clients;  
    /* Initially we iterated over the hashtable for the connected users; this
     * neglects clients who we know are users but haven't fully registered yet
     * (see test_connect_lusers_motd_unregistered in assignment-4) Thus the
     * above code is simpler. Below code did work for assignment-5.
    /*
    conn *user;
    for(user = args->ctx->users; user != NULL; user = user->hh.next) {
        if (strcmp(user->servername, args->ctx->whoami->servername) == 0) {
            num_my_users += 1;
        }
    }
    */

    // Count number of servers connected to ME
    int num_my_servers = 0;  
    conn_hh *server_hh;
    LL_COUNT(args->ctx->connected_servers, server_hh, num_my_servers);

    int OP_COUNT = count_irc_ops(args);
    int channel_count = count_channels(args->ctx);
    int num_services = 0;  // We do not have any services (bots) on our server

    /* users and servers on WHOLE network. Not fully implemented because we
     * did not have to implement SERVER & PASS relaying. Therefore total number
     * of servers is just the number of servers connected locally + myself */
    reply(args, RPL_LUSERCLIENT, 
            ":There are %d users and %d services on %d servers", 
            total_registered, num_services, num_my_servers + 1);
    reply(args, RPL_LUSEROP, "%d :operator(s) online", OP_COUNT);
    reply(args, RPL_LUSERUNKNOWN, "%d :unknown connection(s)", 
            total_conns - total_known);
    reply(args, RPL_LUSERCHANNELS, "%d :channels formed", 
            channel_count);
    reply(args, RPL_LUSERME, ":I have %d clients and %d servers", 
            num_my_users, num_my_servers);
        
    pthread_mutex_unlock(&args->ctx->servers_lock);
    pthread_mutex_unlock(&args->ctx->channels_lock);
    pthread_mutex_unlock(&args->ctx->users_lock);
    return 0;
}


int cmd_oper(handle *args) {
    if (!enough_params(args->params, 2)) {
        reply(args, ERR_NEEDMOREPARAMS, "%s :Not enough parameters", 
                handlers[args->cmd_id].name);
        return -1;
    }
    char *name = args->params[0];
    char *pass = args->params[1];
    if (strcmp(pass, args->ctx->passwd) != 0) {
        reply(args, ERR_PASSWDMISMATCH, ":Password incorrect");
        return -1;
    }
    /* Otherwise, the user succeeds in registering as an OP */
    args->conn->is_operator = true;
    reply(args, RPL_YOUREOPER, ":You are now an IRC operator");

    return 0;
}


/* Ignores parameters of ping and just sends a pong back ASAP */
int cmd_ping(handle *args) {
    char msg[MAX_MSG_LEN];
    sprintf(msg, "PONG %s\r\n", args->server_hostname);
    int bytes = strlen(msg);
    
    /* Lock for reading nick and sending data to all */
    pthread_mutex_lock(&args->conn->conn_lock);
    if (send_all(args->conn->conn_socket, msg, &bytes) < 0) {
        chilog(ERROR, "Socket send_all failed, socket %s message %s", 
                args->conn->conn_socket, msg);
        pthread_mutex_unlock(&args->conn->conn_lock); 
        return -1;
    }
    pthread_mutex_unlock(&args->conn->conn_lock);
    return 0;
}


/* This command does nothing, a silent drop as specified by the instructions */
int cmd_pong(handle *args) {
    return 0;
}


int cmd_whois(handle *args) {
    /* Silently ignore whois if no parameters specified */
    if(!enough_params(args->params, 1)) {
        return 0;
    }
    conn *target = NULL; 
    char *nick = args->params[0];

    /* Manually iterate through hashtable since keys are usernames, not nicks */
    pthread_mutex_lock(&args->ctx->users_lock);
    for(target = args->ctx->users; target != NULL; target = target->hh.next) {
        if (strcmp(target->nickname, nick) == 0) {
            break;
        }
    }
    pthread_mutex_unlock(&args->ctx->users_lock);
    
    /* If no user found, send NOSUCHNICK */
    if (target == NULL) { 
        reply(args, ERR_NOSUCHNICK, "%s :No such nick/channel", nick);
        return -1;
    }

    reply(args, RPL_WHOISUSER, "%s %s %s * :%s", 
        target->nickname, target->username, 
        target->servername, target->realname);
    reply(args, RPL_WHOISSERVER, "%s %s :%s", 
            nick, target->servername, "This server is BORJA's EVIL CHILD :O");
    reply(args, RPL_ENDOFWHOIS, "%s :End of WHOIS list", nick);
    
    return 0;
}


/* 
 * Helper function for cmd_list, sends RPL_LIST reply to channel <chan_name>
 *
 * chan_name - channel to send RPL_LIST to
 *
 * Returns 0 upon success;
 */
int list_onechannel(handle *args, char *chan_name) {
    chan *target_chan = channel_find(args->ctx, chan_name);
    if (target_chan) {
        int user_count = 0;     // Number of users in the channel
        conn_hh *temp_user;
        LL_COUNT(target_chan->users, temp_user, user_count);
        reply(args, RPL_LIST, "%s %d :default_topic", chan_name, user_count);
    }
    return 0;
}


int cmd_list(handle *args) {
    char *chan_name = args->params[0];
    
    /* List given channel */
    if (args->params[0] != NULL) {                  
        list_onechannel(args, chan_name);
        reply(args, RPL_LISTEND, ":End of LIST");
    } 
    
    /* List every channel since no parameter was given */
    else {
        chan *temp_chan;
        pthread_mutex_lock(&args->ctx->channels_lock);
        LL_FOREACH(args->ctx->channels, temp_chan) {
            list_onechannel(args, temp_chan->name);
        }
        pthread_mutex_unlock(&args->ctx->channels_lock);

        reply(args, RPL_LISTEND, ":End of LIST");
    }
    
}


int cmd_mode(handle *args) {
    char *ch_name = args->params[0];
    char *mode = args->params[1];
    char *nick = args->params[2];
    chan *channel = NULL;
    
    /* Check no. of parameters given */
    if (!enough_params(args->params, 3)) {
        chilog(ERROR, "invalid mode command");
        return -1;
    }

    /* Find channel */
    channel = channel_find(args->ctx, ch_name);
    if (!channel) {
        reply(args, ERR_NOSUCHCHANNEL, "%s :No such channel", ch_name);
        return -1;
    }

    /* Only accept +o/-o as modes */
    if (strcmp(mode, "+o") != 0 && strcmp(mode, "-o") != 0) {
        reply(args, ERR_UNKNOWNMODE, "%c :is unknown mode char to me for %s",
                mode[1], ch_name);
        return -1;
    }

    /* Find user handle based on nick given */
    conn_hh *user_hh = channel_find_nick(channel, nick);
    if (!user_hh) {
        reply(args, ERR_USERNOTINCHANNEL, "%s %s :They aren't on that channel",
                nick, ch_name);
        return -1;
    }
    
    conn_hh* sending_user_hh = channel_find_user(channel, 
                                                args->conn->username);
    /* Issueing user is neither IRC nor channel operator */
    if (!sending_user_hh->is_channel_operator
        && !sending_user_hh->conn->is_operator) {
        reply(args, ERR_CHANOPRIVSNEEDED, "%s :You're not channel operator",
                ch_name);
        return -1;
    }

    /* Set relay MODE message */
    char* buf = (char*) calloc(MAX_MSG_LEN, sizeof(char));
    sprintf(buf, "%s %s", mode, user_hh->conn->nickname);

    int op_status = -1;  // 0 signals -o command, 1 signals +o cmd
    /* Execute either -o or -o */
    if (strcmp(mode, "+o") == 0) {
        op_status = 1;
    } else if (strcmp(mode, "-o") == 0) {
        op_status = 0;
    }

    if (op_status < 0) {
        chilog(INFO, "Invalid MODE %s received", mode);
        return -1;
    }
    
    /* Set channel operator*/
    channel_set_op(channel, user_hh, op_status);

    /* Relay MODE message */
    pthread_mutex_lock(&channel->chan_lock);
    chilog(TRACE, "Channel lock set");

    conn_hh* t;
    LL_FOREACH(channel->users, t) {
        broadcast(channel->name, buf, "MODE", 
                    sending_user_hh->conn, t->conn, false, 0);
    }

    pthread_mutex_unlock(&channel->chan_lock);
    chilog(TRACE, "Channel lock removed");
    return 0;
}


/* See handlers.h
 * NOTE: This function does not touch rt_lock; 
 * only the relay thread function touches rt_lock
*/        
int relay_message(relay_args *rt_args, server_ctx *ctx) {
    chilog(DEBUG, "Relay message entered");
    /* which users/servers we should avoid relaying to */
    char *ignored_username = ""; 
    char *ignored_servername = "";

    /* TODO: NEED TO add locking here, seems like not everything locked */
    if (rt_args->exclude_sender) {
        if (rt_args->msg_origin->user_flag) {
            ignored_username = rt_args->msg_origin->username;
        } else if (rt_args->msg_origin->servername != NULL) {
            ignored_servername = rt_args->msg_origin->servername;
        }
    }

    // Setting below to NULL causes no prefixes in broadcast
    conn *origin_conn = rt_args->msg_origin;; 
    if (rt_args->no_prefix) {
        origin_conn = NULL;
    }

    /* First deal with relaying to servers, then relaying to users */
    if (rt_args->relay_servers) {
        pthread_mutex_lock(&ctx->servers_lock);
        char *server_msg[MAX_MSG_LEN];
        conn_hh *server;
        LL_FOREACH(ctx->connected_servers, server) {
            if (strcmp(server->conn->servername, ignored_servername) != 0) {
                chilog(DEBUG, "RELAYED to server %s: <%s> <%s> <:%s>", 
                        server->conn->servername, 
                        rt_args->CMD, 
                        rt_args->short_param,
                        rt_args->long_param);

                chilog(DEBUG, "PREFIX <%s>", rt_args->prefix);
                int prefix_fmt = 0;  // Prefix of :<nick>
                if (broadcast_gen(rt_args->short_param, rt_args->long_param, 
                                rt_args->CMD, origin_conn, 
                                server->conn, true, prefix_fmt, 
                                rt_args->prefix) == -1) {
                            chilog(ERROR, "relay of %s failed to %s", 
                                    rt_args->CMD, server->conn->servername);
                }
            }
        }
        pthread_mutex_unlock(&ctx->servers_lock);
    }
    
    /* Now deal with relaying to users. 
       Users is hashtable, so can't use LL_FOREACH */
    if (rt_args->relay_users) {
        pthread_mutex_lock(&ctx->users_lock);
        char *user_msg[MAX_MSG_LEN];
        conn *user;
        for (user = ctx->users; user != NULL; user = user->hh.next) {
            if (strcmp(user->username, ignored_username) != 0) {
                int prefix_fmt = 0;  // Full nick:username:hostname prefix
                if (broadcast_gen(rt_args->short_param, rt_args->long_param, 
                    rt_args->CMD, rt_args->msg_origin, user, 
                    true, 0, rt_args->prefix) == -1) {
                            chilog(ERROR, "relay of %s failed to %s", 
                                    rt_args->CMD, user->username);
                }
            }
        }
        pthread_mutex_unlock(&ctx->users_lock);
    }
    chilog(DEBUG, "Relay message done");
    return 0;
}

/* See above function declaration */
int count_irc_ops(handle *args) {
    int total_ops = 0;
    for (conn *s = args->ctx->users; s != NULL; s=s->hh.next) {
        if (s->is_operator) total_ops++; // global ops
    }
    return total_ops;
}


/* See above function declaration */
bool nickname_available(handle *args, char *nickname) {
    for (conn *s = args->ctx->users; s != NULL; s = s->hh.next) {
        if (strcmp(s->nickname, nickname) == 0) {
            return false;
        }
    }
    return true;
}


/* See handler.h */
int register_user(handle *args, conn *new_user) {
    conn *added_user;
    if (new_user == NULL) {  // User has directly registered via NICK
        added_user = args->conn;
        added_user->servername = args->ctx->whoami->servername;
        chilog(INFO, "Added user %s with server %s", added_user->username,
                                                     added_user->servername);
    } else {  // Received a relayed message that registers a new user
        added_user = new_user;
        added_user->servername = strdup(args->prefix);
        if (args->prefix == NULL) {
            chilog(ERROR, "relayed NICK message has no server prefix");
            return -1;
        }
    }

    chilog(INFO, "Adding user <%s> to database...", 
            added_user->username);

    args->ctx->num_registered++;

    /* Relay registration to other servers using special server format
    /* NICK <nickname> <hopcount> <username> <host> <servertoken>
        <umode> <realname> */

    pthread_mutex_lock(&args->ctx->rt_lock);
    char nick_msg[MAX_MSG_LEN];

    /* Prefix should have server in prefix, so msg_origin should servername */
    args->ctx->rt_args->msg_origin = args->conn;
    args->ctx->rt_args->CMD = strdup("NICK");
    
    /* Next 3 fields are given in the instructions as these values */
    char *nickname = added_user->nickname;
    char *hopcount = "1";
    char *servertoken = "1";
    char *umode = "+";
    char *username = added_user->username;
    char *host = added_user->hostname;
    
    sprintf(nick_msg, "%s %s %s %s %s %s", 
            nickname, hopcount, username, host, servertoken, umode);

    args->ctx->rt_args->short_param = strdup(nick_msg);
    args->ctx->rt_args->long_param = strdup(added_user->realname);
    args->ctx->rt_args->exclude_sender = true;
    args->ctx->rt_args->relay_servers = true;
    args->ctx->rt_args->no_prefix = false;
    if(args->prefix) {
        args->ctx->rt_args->prefix = strdup(args->prefix);
    } else {
        args->ctx->rt_args->prefix = strdup(args->conn->servername);
    }
    
    pthread_cond_signal(&args->ctx->rt_cv);  
    pthread_mutex_unlock(&args->ctx->rt_lock);
    
    /* add user to hashtable */
    return add_user(&args->ctx->users, added_user);
}


/* See handler.h */
conn_hh* find_server(conn_hh* servers, char* servername) {
    conn_hh* ret = NULL;
    conn_hh* t = NULL;
    if (servers != NULL) {
        LL_FOREACH(servers, t) {
            if (cmp_server(t, servername) != NULL) {
                ret = cmp_server(t, servername);
            }
        }    
    }
    return ret;
}


/* See above function declaration */
conn_hh* cmp_server(conn_hh* server, char* servername) {
    if (server->conn != NULL && server->conn->servername != NULL) {
        if (strcmp(server->conn->servername, servername) == 0) {
            return server;
        }
    }

    return NULL;
}


/* See handlers.h */
void reset_relay_args(relay_args *rt_args) {
    rt_args->msg_origin = NULL;

    /* Clean up string arguments. This why we need COPIES of the strings */
    if (rt_args->CMD) free(rt_args->CMD);
    rt_args->CMD = NULL;
    if (rt_args->short_param) free(rt_args->short_param);
    rt_args->short_param = NULL;
    if (rt_args->long_param) free(rt_args->long_param);
    rt_args->long_param = NULL;

    rt_args->exclude_sender = false;
    rt_args->relay_users = false;
    rt_args->relay_servers = false;
    rt_args->no_prefix = false;

    if (rt_args->prefix) free(rt_args->prefix);
    rt_args->prefix = NULL;
}

#endif
