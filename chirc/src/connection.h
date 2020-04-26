#ifndef CHIRC_CONNECTION_H
#define CHIRC_CONNECTION_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>

#include "constants.h"
#include "uthash.h"
#include "log.h"

/* Different status of any user connection 
 *
 * user status: > 0
 * server status: < 0
 */
typedef enum {
    SERVER_CONNECTED = -3,
    SERVER_GIVEN = -2,
    PASS_GIVEN = -1,
    NOT_REGISTERED = 0,
    NICK_VALID = 1,
    USER_VALID = 2,
    REGISTERED = 3
} conn_status;



/* Struct to store the registration information of a connection 
 * None of these fields should be a pointer to stack memory addresses
 * HELPER FUNCTIONS handle conn_lock unlocking/locking. 
 * We can turn conns into a linked list (easier searching than using conn_hh)
 */
typedef struct conn {
    struct conn* next; // For linked list functionality; default is NULL. TODO: remove conn_hh, refactor everything into conn *; cleaner design
    UT_hash_handle hh;          // So we can hash connections

    bool user_flag;    // User vs another server
    bool is_operator;  // Global IRC operator status

    char *username;
    char *realname; 
    char *nickname;
    char *hostname;    // used both by server & client connections

    char *servername;  // of conn server (or of the server user connected to)
    char *password;    // for server connections
    char *port;

    conn_status status;
    int conn_socket;            // Active socket used to communicate with conn
    pthread_mutex_t conn_lock;  // used R/W from fields & safe send
} conn;



/* Connection handle for ut_list; linked list node for a user in channel */
struct conn_handle {
    struct conn_handle* next;
    bool is_channel_operator;
    conn* conn;
};
typedef struct conn_handle conn_hh;


/* 
 * Channel struct 
 *
 * NOTE: the HELPER FUNCTIONS handle the unlocking/locking of chan_lock.
 */
typedef struct chan {
    char* name;
    struct chan* next;          // Linked list functionality; needed for utlist
    conn_hh* users;             // user handle to create LL of users
    pthread_mutex_t chan_lock;  // modification lock
} chan;


/* 
 * Holds pertinent information like whether to relay to
 * users, servers, and the message to relay to each
 * When server_msg and user_msg are not NULL, we relay those messages out
 * to the corresponding users/messages
 * 
 * format: "<prefix> <CMD> <long_param>"
 * prefix is full ":<nickname>!<username>@<hostname>" for user relays, 
 *                ":<nickname>"                       for relays to servers
 * 
 * NOTE: ANY char * arguments should have copies of the original strings
 * for proper memory management
 * 
 * It should be the caller of the relay thread's responsibility to make sure
 * these fields are set appropriately in the relay_args struct in server_ctx
 * They are automatically zeroed to NULL after every call of relay_message(...)
 */
typedef struct relay_args {
    
    /* The following fields are used when a server starts a relay */

    conn *msg_origin;     // Server which sent the last relay command
    char *CMD;            // Command that we are relaying, e.g. NICK
    
    char *short_param;    // params before long param; crammed into 1 str
    char *long_param;     // last parameter in message to relay out
    
    bool exclude_sender;  // Whether to ignore relaying message to sender
                          // For server commands, this should always be true

    bool relay_users;     // Relay msg to users connected to server
    bool relay_servers;   // Relay msg to connected servers 
    bool no_prefix;       // If true, then do not include prefix in message

    /* The following fields are used to chain relay messages around */
    char *prefix;         // This overrides auto prefix when provided      
} relay_args;


/* Server context struct that contains information
 * that needs to be shared across all worker threads.
 * 
 * LOCK INFO: these two global locks must be handled manually when appropriate
 * 
 * users_lock - used when users data is needed
 * channels_lock - used when channels data is needed
 * 
 * users_lock and channels_lock are not called by helper functions 
 * to prevent deadlock
 */
typedef struct {
    int num_known;              // (LOCAL) KNOWN (register + notreg) OTHER conns

    int num_connections;        // (LOCAL) Unknown + known(notreg) + regist
                                // client & server connections to this server
    int local_clients;          // (LOCAL) total of regis + unregis known CLIENTS
                                // Passes assign5 w/o this but assign4 needs it

    int num_registered;         // (GLOBAL) total registered USERS
    
    conn *users;                // (GLOBAL) hash table to REGISTERED users
    chan *channels;             // (GLOBAL) linked list of all channels 

    conn_hh *allowed_servers;       // Storing all allowed servers
    conn_hh *connected_servers;     // List of connected servers to host

    conn *whoami;                   // Identifying host server

    char *passwd; 
    pthread_mutex_t users_lock;     // Users list registration lock
    pthread_mutex_t channels_lock;  // Channels list lock
    pthread_mutex_t servers_lock;   // Present servers list lock

    pthread_mutex_t rt_lock;        // Used to synchronize relay thread
    pthread_cond_t rt_cv;           // condvar to signal relay thread wake 
    relay_args *rt_args;

} server_ctx;

/* 
 * Constructor for new connection
 * 
 * user: flag to set user_flag in struct
 * Returns: new user
 */
conn* connection_new(bool user);



/* 
 * Display connection contents 
 *
 * Returns: nothing
 */
void connection_show(conn* connection);


/* 
 * Checks if user & nick valid and sets registered flag 
 * 
 * Returns: true if user is already registered, false if not
 */
bool connection_is_registered(conn* user);


/* 
 * Obtains and sets hostname for connection
 * 
 */
int connection_set_hostname(conn* connection);


/* 
 * Source: Beej's guide
 * 
 * Returns: nothing
 */
int connection_set_hostname(conn* connection);


/* 
 * Frees all non-NULL fields in connection and then frees connection
 * 
 * Returns: 0 upon succes, -1 upon failure
 */
int connection_destroy(conn* connection);

#endif