/*
 *  server.c: running an IRC server
 *
 *  Brain of the IRC program. Handles incoming connections and spawns new
 *  threads to service the client.
 *
 */

#ifndef CHIRC_SERVER_C
#define CHIRC_SERVER_C

#include "server.h"
#include "uthash.h"
#include "constants.h"
#include "log.h"
#include "connection.h"
#include "channel.h"
#include "message.h"
#include "reply.h"


/* See server.h */
void server_main(char* port, char* passwd, char* host, char* network_file) {
    server_ctx *ctx = calloc(1, sizeof(server_ctx));
    ctx->num_known = 0;
    ctx->num_connections = 0;
    ctx->local_clients = 0;
    ctx->num_registered = 0;
    ctx->passwd = passwd;

    /* LL head's have to be initialized to NULL */
    ctx->users = NULL;
    ctx->channels = NULL;
    ctx->allowed_servers = NULL;

    /* Set whoami arg so that we can access our own host info later*/
    ctx->whoami = connection_new(false); 

    ctx->rt_args = calloc(1, sizeof(relay_args));

    /* Initialize ctx locks for users list, channels list, and servers list */
    pthread_mutex_init(&ctx->users_lock, NULL);
    pthread_mutex_init(&ctx->channels_lock, NULL);
    pthread_mutex_init(&ctx->servers_lock, NULL);

    pthread_mutex_init(&ctx->rt_lock, NULL);
    pthread_cond_init(&ctx->rt_cv, NULL);

    /* Socket set-up */
    int server_socket;
    int client_socket;
    struct sockaddr_storage client_addr; 
    socklen_t sin_size;
    char ipstr[INET6_ADDRSTRLEN];
    int sock_optval;

    struct addrinfo hints,
                    *res,
                    *p;    


    /* Process network specification file if present and exit if ERROR */
    if (network_file != NULL && (process_network_file(ctx, network_file) < 0)) {
        exit(-1);
    }
    
    /* Hints addrinfo to help returning addresses we can use */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    chilog(TRACE, "HOST: <%s>", host);

    /* Get host & port from network file */
    /* If not in network file, then update whoami later */
    if (network_file != NULL) {
        /* host is the -s servername specified when network file given */
        if (host != NULL) {
            conn_hh* found = find_server(ctx->allowed_servers, host);

            /* Servername exists in network file*/
            if (found != NULL) {
                port = strdup(found->conn->port);
                host = strdup(found->conn->hostname);
               
                /* Creating host server struct whoami */
                conn* this_server = ctx->whoami;
                this_server->user_flag = false;
                this_server->servername = strdup(found->conn->servername);
                this_server->hostname = strdup(found->conn->hostname);
                this_server->port = strdup(found->conn->port);
                this_server->password = strdup(found->conn->password);          

            } else {
                chilog(CRITICAL, "Server <%s> was not found in network file",
                        host);
                exit(-1); 
            }
        } 
    } 

    /* Call getaddrinfo with the host and port specified in the command line */
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        chilog(ERROR, "getaddrinfo() failed");
        exit(-1);
    }

    /* Connection creation (socket, bind, listen) */
    for (p = res; p != NULL; p = p->ai_next) {
        /* Create socket */
        if ((server_socket = socket(p->ai_family,
                                     p->ai_socktype, p->ai_protocol)) == -1) {
            chilog(ERROR, "Socket socket() failed");
            exit(-1);
        }

        /* Eliminates "address already in use" error from bind */
        if (setsockopt(server_socket, 
                        SOL_SOCKET, 
                        SO_REUSEADDR, 
                        &sock_optval, sizeof(int)) == -1) {
              chilog(ERROR, "Socket setsockopt() failed");
              close(server_socket);
              exit(-1);
        }

        if (bind(server_socket, p->ai_addr, p->ai_addrlen) == -1) {
            chilog(ERROR, "Socket bind() failed");
            close(server_socket);
            exit(-1);
        }
        
        if (listen(server_socket, MAX_QUEUED_CONNS) == -1) {
            chilog(ERROR, "Socket listen() failed");
            close(server_socket);
            exit(-1);
        }

        chilog(INFO, "Waiting for a connection... ");
        break;
    }

    /* Set whoami now for this server.
       connection_set_hostname only works for remote connections, not local */
    if (!network_file) {
        ctx->whoami->port = port;
        char* hostname = (char*) calloc(MAX_MSG_LEN, sizeof(char));
        gethostname(hostname, MAX_MSG_LEN);
        ctx->whoami->servername = hostname;
        ctx->whoami->hostname = hostname;
        chilog(INFO, "set hostname for server to %s", ctx->whoami->hostname);
    }
    freeaddrinfo(res);

    /* Set and change mask of blocked signals */
    sigset_t set;
    sigemptyset (&set);
    sigaddset(&set, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) 
    {
        perror("Unable to mask SIGPIPE");
        exit(-1);
    }

    /* Buffer to store received messages on the server */
    char* recv_msg;
    if ((recv_msg = (char *) calloc(MAX_MSG_LEN, sizeof(char))) == NULL) {
        chilog(ERROR, "Could not calloc recv_msg");
    }
    
    /* Start relay thread */
    pthread_t relay_thread;
    if (pthread_create(&relay_thread, NULL, 
                        start_relay_thread, ctx) != 0) {
            chilog(CRITICAL, "Could not create the relay thread. Terminating");
            close(client_socket);
            exit(-1);  // Since relay thread is essential
    }
    
    chilog(TRACE, "Entering into connection accepting loop");
    worker_args *wa;
    pthread_t worker_thread;
    while (1) {
        sin_size = sizeof(client_addr);

        /* Accept connection */
        if ((client_socket = accept(server_socket, 
                                    (struct sockaddr *) &client_addr, 
                                    &sin_size)) == -1) {
            chilog(ERROR, "Socket accept() failed");
            close(server_socket);
            exit(-1);
        }

        chilog(INFO, "Connection accepted");
        /* Creating workers args */
        wa = calloc(1, sizeof(worker_args));
        wa->socket = client_socket;
        wa->ctx = ctx;
        wa->new_conn = NULL;

        /* Spawning thread to service client */
        pthread_t worker_thread;
        if (pthread_create(&worker_thread, NULL, service_client, wa) != 0) {
            chilog(ERROR, "Could not create a worker thread");
            free(wa);
            close(client_socket);
            pthread_exit(NULL);
        }

    }
    free(ctx->rt_args);
    free(recv_msg);    
}


/* See server.h */
void *service_client(void *args) {
    worker_args *wa;
    int client_socket;
    server_ctx *ctx;
    
    conn* current_conn;
    bool user = false;

    char buffer[BUFFER_SIZE];  // Stores incoming raw recvs
    int index = 0;             // Current write position in buffer
    int nbytes = 0;            // Number of bytes received by recv
    char *recv_msg;            // Stores full messages extracted from buffer 

    bool error = false;

    /* Set parameters from passed args from main thread */
    wa = (worker_args*) args;
    client_socket = wa->socket;
    ctx = wa->ctx;
    current_conn = wa->new_conn;
    
    pthread_mutex_lock(&ctx->users_lock);
    pthread_mutex_lock(&ctx->servers_lock);
    ctx->num_connections++;
    pthread_mutex_unlock(&ctx->servers_lock);
    pthread_mutex_unlock(&ctx->users_lock);

    /* Init recv_msg */
    if ((recv_msg = (char*) calloc(MAX_MSG_LEN, sizeof(char))) == NULL) {
        chilog(ERROR, "Could not calloc recv_msg");
    }

    /* If no connection given by wa, create new conn struct */
    if (current_conn == NULL) {
        user = true;
        current_conn = connection_new(user);
        current_conn->conn_socket = client_socket;
    }
    connection_set_hostname(current_conn);


    /* Receiving bytes from connection and processing */
    while (1) {
        
        /* Read from socket */
        nbytes = recv(client_socket, buffer + index, MAX_MSG_LEN, 0);
        index = index + nbytes; // current position in buffer

        if (nbytes == 0) {
            chilog(INFO, "Client closed the connection");
            goto client_exit;
        }
        else if (nbytes == -1) {
            chilog(ERROR, "Socket recv() failed");
            goto client_exit;
        }
        else {
            chilog(TRACE, "Buffer: %s", buffer);                
        }

        chilog(TRACE, "server.c: - nbytes received: %i", nbytes);
        chilog(TRACE, "current buffer index: %i", index);

        /* Process the information stored in the buffer for commands */
        int return_code = process_buffer(current_conn, 
                                         buffer, recv_msg, &index, ctx);
        
        /* If user quits, handle closed connection */
        if (return_code == QUIT_SIGNAL) {
            goto client_exit;
        }
    }

/* 
 * Handles a closed connection by client with appropriate locking
 */
client_exit:
    free(recv_msg);
    if (current_conn != NULL) {
        /* Set users lock & channels lock */
        pthread_mutex_lock(&ctx->users_lock);
        pthread_mutex_lock(&ctx->channels_lock);
        
        /* Remove user from all global state */
        if (current_conn->user_flag) {
            remove_user_all_channels(ctx, current_conn);
            delete_user(&ctx->users, current_conn);    
        }
        
        ctx->num_connections--;
        ctx->num_registered--;
        ctx->num_known--;
        ctx->local_clients--;

        pthread_mutex_unlock(&ctx->channels_lock);
        pthread_mutex_unlock(&ctx->users_lock);
        close(client_socket);
        pthread_exit(NULL);    
    }
    
}


/* See server.h */
int connect_to_server(char *servername, char *port, server_ctx *ctx,
                      conn* new_server) {
    chilog(INFO, "connect_to_server called by %s", ctx->whoami->servername);
    
    pthread_mutex_lock(&ctx->servers_lock);
    
    /* First make sure we aren't already connected to this server */
    conn_hh* other_server = find_server(ctx->connected_servers, servername);
    if (other_server) {
        chilog(ERROR, "Already connected to server %s; can't connect", 
                servername);
        pthread_mutex_unlock(&ctx->servers_lock);
        free(new_server);
        return -1;
    }

    chilog(INFO, "connect_to_server called 2");

    /* Find other server */
    other_server = find_server(ctx->allowed_servers, servername);
    pthread_mutex_unlock(&ctx->servers_lock);

    /* Server members needed */
    char *other_pass = other_server->conn->password;  // Other server's password
    char *server_hostname = other_server->conn->hostname;
    new_server->hostname = strdup(server_hostname);
    new_server->servername = strdup(servername); 
    new_server->password = strdup(other_pass);

    /* Server given to be added to connected_servers */
    conn_hh* new_server_hh = (conn_hh*) calloc(1, sizeof(conn_hh));
    new_server_hh->conn = new_server;

    /* Open an *active* socket with the other server */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    /* NOTE: no ai_PASSIVE flag since this is an active socket */

    chilog(INFO, "Trying connect to server hostname %s", server_hostname);
    
    if (getaddrinfo(server_hostname, port, &hints, &res) != 0) {
        chilog(ERROR, "getaddrinfo() failed in connect_to_server");
        return -1;
    }
    
    /* Create socket for other server */
    int sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock_fd == -1) {
        chilog(ERROR, "Active socket creation on connect_to_server failed");
        return -1;
    }

    /* Set new server connection socket in struct */
    new_server->conn_socket = sock_fd;

    if (connect(sock_fd, res->ai_addr, res->ai_addrlen) == -1) {
        chilog(ERROR, "connect() in connect_to_server failed");
        chilog(INFO, "sock_fd value for connect(): %d", sock_fd);
        return -1;
    }

    other_server->conn->conn_socket = sock_fd;

    /* Create listening thread to deal with this created active socket */
    pthread_t worker_thread;   
    worker_args *wa = calloc(1, sizeof(worker_args));

    wa->socket = sock_fd;
    wa->ctx = ctx;
    wa->new_conn = new_server;

    /* Spawning thread to service client */
    if (pthread_create(&worker_thread, NULL, service_client, wa) != 0) {
        chilog(ERROR, "Could not create a worker thread");
        free(wa);
        close(sock_fd);
        pthread_exit(NULL);
    }

    /* TODO: refactor. */
    /* Constructing PASS & SERVER replies */
    char pass_msg[MAX_MSG_LEN];
    char* pass_long_param = "0210 chirc|3.11";
    sprintf(pass_msg, "%s %s", other_server->conn->password, pass_long_param);

    char server_msg[MAX_MSG_LEN];
    char* token = "1";  // Specified in the instructions
    char* serverinfo = ":chirc server";  // arbitrary string per instructs
    char* active_server_name = strdup(ctx->whoami->servername);
    sprintf(server_msg, "%s %s %s", active_server_name, token, serverinfo);

    /* Don't send prefix messages in initial reply */
    broadcast_server(NULL, new_server, "PASS", pass_msg);
    broadcast_server(NULL, new_server, "SERVER", server_msg);

    return 0;
};


/* See server.h */
void *start_relay_thread(void *args) {
    // TODO: FINISH THIS FUNCTION
    chilog(DEBUG, "Relay Thread Started");
    server_ctx *ctx = (server_ctx *) args;
    pthread_mutex_lock(&ctx->rt_lock);
    reset_relay_args(ctx->rt_args);  // initialize rt_args
    /* Keep listening for relay requests FOREVER hahahahaha */
    while (true) {

        /* This inner loop is to deal with spurious wakes; they'll be ignored */
        while (ctx->rt_args->msg_origin == NULL) {
            pthread_cond_wait(&ctx->rt_cv, &ctx->rt_lock); 
        }

        /* Received signal to relay: relay whatever is in relay_args */
        if (relay_message(ctx->rt_args, ctx) == -1) {
            chilog(ERROR, "Relay thread relay failed for command %s %s", 
                    ctx->rt_args->CMD, ctx->rt_args->long_param);
        }
        reset_relay_args(ctx->rt_args);
    }
    /* Clean up locks; code currently does not get here */
    pthread_mutex_unlock(&ctx->rt_lock);
    pthread_mutex_destroy(&ctx->rt_lock);
    pthread_cond_destroy(&ctx->rt_cv);
    pthread_exit(NULL);
}

/* See server.h */
int process_network_file(server_ctx* ctx, char* network_file) {
    /* Open network file */
    FILE* fp = fopen(network_file, "r");

    if (!fp) {
        chilog(ERROR, "Cannot open network file <%s>", network_file);
        return -1;
    }

    char buf[BUFFER_SIZE];
    int row_count = 0;
    int field_count = 0;

    /* Get 1024 bytes from file and store in buffer to iterate over */
    while (fgets(buf, BUFFER_SIZE, fp)) {
        field_count = 0;
        row_count++;

        /* Set up LL for allowed servers */
        conn* allowed_server = (conn*) calloc(1, sizeof(conn));
        conn_hh* allowed_server_hh = (conn_hh*) calloc(1, sizeof(conn_hh));
        allowed_server_hh->conn = allowed_server;
        LL_APPEND(ctx->allowed_servers, allowed_server_hh);

        char *save_ptr;  // used to save position for strtok_r
        char *field = strtok_r(buf, ",", &save_ptr);
        

        /* Setting appropriate fields */
        while (field) {
            if (field_count == 0) {
                allowed_server->servername = strdup(field);
            }
            if (field_count == 1) {
                allowed_server->hostname = strdup(field);
            }
            if (field_count == 2) {
                allowed_server->port = strdup(field);
            }
            if (field_count == 3) {
                /* fgets appends newline to end of file */
                field[strlen(field)-1] = '\0';  
                allowed_server->password = strdup(field);
            }

            field = strtok_r(NULL, ",", &save_ptr);

            field_count++;
        }

        connection_show(allowed_server);
    }


    /* Close file */
    fclose(fp);

    return 0;
}


/* See server.h */
int process_buffer(conn *current_conn, char *buffer,
                    char *recv_msg, int *index, server_ctx *ctx) {
    
    bool keep_scanning = true;  // Assume multiple messages in 1 recv possible
    int ret;

    while (keep_scanning) {
        keep_scanning = false;
        for (int t = 0; t < *index - 1; t++) {
            if (buffer[t] == '\r' && buffer[t+1] == '\n') {
                int msg_len = t;
                
                /* Copy into recv_msg up t chars (excluding CRLF) */
                memcpy(recv_msg, buffer, msg_len); 
                recv_msg[msg_len] = '\0';
                
                /* Check correctness */
                chilog(DEBUG, "Received message <%s> from userstatus <%d>", 
                            recv_msg, current_conn->user_flag);

                /* Send recv_msg to be parsed() */
                ret = process_message(recv_msg, current_conn, ctx);
                if (ret == -1) {
                    chilog(ERROR, "process_message failed on %s\n", recv_msg);
                }
                
                /* Shifts index to place new recvs, 2 is from \r\n */
                *index -= msg_len + 2;

                /* Clears recv_msg to be reused again */
                memset(recv_msg, 0, MAX_MSG_LEN * sizeof(char));

                /* Shifts remaining unprocessed parts of buffer leftward */
                memmove(buffer, 
                        buffer + msg_len + 2, BUFFER_SIZE - (msg_len + 2));
                
                /* Fills the extra bits to the right with 0 */
                memset(buffer + BUFFER_SIZE - (msg_len + 2), 0, (msg_len + 2));

                /* Parse rest of buffer for additional messages */
                keep_scanning = true; 
                break;
            }
        }
    }
    return ret;
}


/* See handlers.h */
int add_user(conn **users, conn *new_user) {
    conn *s = NULL;
    HASH_FIND_STR(*users, new_user->username, s);  
    if (s == NULL) {  // user is not in the table
        chilog(TRACE, "Adding user <%s> to hashtable...", new_user->username);
        HASH_ADD_STR(*users, username, new_user);  
    } else {
        chilog(ERROR, "tried to add a user with the same username into table");
        return -1;
    }
    return 0;
}


/* See handlers.h */
void print_users(conn *users) {
    conn *s;
    chilog(DEBUG, "Printing users hashtable:");
    for(s=users; s != NULL; s=s->hh.next) {
        chilog(DEBUG, "(username: <%s>, nickname: <%s>)\n", 
                        s->username, s->nickname);
    }
}


/* See server.h */
int delete_user(conn **users, conn *user) {
    chilog(TRACE, "Deleting user...");
    if (users != NULL && user->username != NULL) {
        char *username = user->username;
        user = NULL;
        HASH_FIND_STR(*users, username, user); 
        if (user == NULL) {
            chilog(TRACE, "Could not find user %s for deletion", username);
            return -1;
        } else {
            HASH_DEL(*users, user);
            connection_destroy(user);
            chilog(TRACE, "Deleted user %s", username);
            return 0;
        }
    }
}


#endif