#ifndef CHIRC_SERVER_H
#define CHIRC_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "connection.h"

/* 
 * NOTE: server_ctx struct is declared in connection.h because handlers.h
 * needs to access it. Same applies for connection structs and some funcs
 */


/* 
 * Main thread for the server which keeps open a passive socket and 
 * spawns worker threads.
 * 
 * port: string with port number, e.g. "7776"
 * passwd: string with password
 * host:  string containing host to use for server
 * network_file: path to a file argument for network; not used since no MOTD
 * 
 * Returns: nothing.
 */
void server_main(char* port, char* passwd, char* host, char* network_file);


/* Arguments to be passed to worker thread */
typedef struct {
    int socket;         // address of the accepted client socket
    server_ctx* ctx;
    conn* new_conn;     // a new connection to be used in new thread 
} worker_args;

/* 
 * Deletes user from hash table accessed by users.
 *
 * Is called upon user quit/disconnect.
 * 
 * users: pointer to connection pointer to iterate over
 * user: user connection to delete 
 * 
 * Returns: 0 on success, -1 on failure.
 *
 */
int delete_user(conn** users, conn *user);

/*
 * Handles the thread dealing with an individual client. Creates new user.
 * Receives messages over socket and passes them on to be processed. Also
 * handles a user closing a connection.
 *
 * 
 * args: pointer to a worker_args struct; it must be (void *)
 *       to work with pthreads properly
 *
 * Returns: nothing.
 */
void *service_client(void *args);


/*
 * Handles the thread dealing with relaying messages both to clients and to
 * other servers connected to this server. The relay thread sleeps until
 * a handler function unlocks rt_lock and signals for it to wake up
 * via the conditional variable rt_cv. The function signalling the relay thread
 * should make sure to 
 * 1. Acquire rt_lock
 * 2. Provide the correct arguments to rt_args
 * 3. Unlock rt_lock and send signal to the relay thread via the condvar
 * 
 * args: pointer to the server_ctx struct; it must be (void *)
 *       to work with pthreads properly
 *
 * Returns: nothing.
 */
void *start_relay_thread(void *args);

/*
 * Processes buffer received from user socket by service_client
 *
 * index: length of buffer
 * recv_msg: heap-allocated (char*) memory to write to
 * 
 * Returns: 0 on success, -1 on failure. 
 */
int process_buffer(conn *current_user, char *buffer, char *recv_msg,
                    int *index, server_ctx *ctx);


/*
 * Process the network specification file to specify the IRC network
 *
 * network_file: the network specification file
 * ctx: global server context
 *
 * Returns: 0 on success, -1 on failure.
 */
int process_network_file(server_ctx *ctx, char *network_file);

/*
 * Attempts to create an active connection to the server specified
 * and spawns a worker thread to service the given server if successful, 
 * adding it to the list of connected servers (even though it's not registered)
 * we still relay messages to it
 *
 * servername - the name of the other server, as a string
 * port - port of other server, as a string
 * new_server - connection for the newly connected server that needs:
 *              1) port 
 *              2) status
 *             
 *              3) hostname (optional, current design choice: let the service_client set the hostname for new_server)
 *              to be set.                
 *
 * new_server is passed on to service_client, who will handle the connection
 * like normal.
 *
 * Returns: 0 on success, -1 on failure.
 */
int connect_to_server(char *servername, char *port, server_ctx *ctx, conn* new_server);
#endif