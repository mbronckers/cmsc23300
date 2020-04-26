/* 
 * connection.c - all functions related to connectino (user) interactions 
 *                and creation
 * 
 * Use these functions to create new users, log users, register them, etc.
 *
 */

#ifndef CHIRC_CONNECTION_C
#define CHIRC_CONNECTION_C

#include "connection.h"

/* See connection.h */
conn* connection_new(bool user) {
    conn* new_conn;
    if ((new_conn = (conn*) calloc (1, sizeof(conn))) == NULL) {
        chilog(ERROR, "Could not calloc new user connection");
    }

    if (user) {
        new_conn->user_flag = true;
    } else {
        new_conn->user_flag = false;
    }
    
    new_conn->next = NULL;
    new_conn->is_operator = false;

    new_conn->username = NULL;
    new_conn->realname = NULL;
    new_conn->nickname = NULL;
    new_conn->hostname = NULL;

    new_conn->servername = NULL;
    new_conn->password = NULL;
    new_conn->hostname = NULL;
    

    new_conn->status = NOT_REGISTERED;
    new_conn->conn_socket = -1;  // Placeholder for no socket
    pthread_mutex_init(&new_conn->conn_lock, NULL);
    return new_conn;
}


/* See connection.h */
void connection_show(conn* conn) {
    chilog(TRACE, "Showing connection...");
    if (conn != NULL) {
        pthread_mutex_lock(&conn->conn_lock);
        if (conn->user_flag) {
            if (conn->username != NULL)
                chilog(TRACE, "Username: <%s>", conn->username);    
            if (conn->nickname != NULL)
                chilog(TRACE, "Nickname: <%s>", conn->nickname);
            if (conn->is_operator != false)
                chilog(TRACE, "This user is an operator", conn->nickname);
            if (conn->hostname != NULL)            
                chilog(TRACE, "Hostname: <%s>", conn->hostname);
            if (conn->servername != NULL)
                chilog(TRACE, "Connected to server: <%s>", conn->servername);

            chilog(TRACE, "User status: %i", conn->status);
        } else {
            if (conn->servername != NULL)
                chilog(TRACE, "Server name: <%s>", conn->servername);
            if (conn->hostname != NULL)
                chilog(TRACE, "Hostname: <%s>", conn->hostname);
            if (conn->port != NULL)
                chilog(TRACE, "Port: <%s>", conn->port);
            if (conn->password != NULL)
                chilog(TRACE, "Server password: <%s>", conn->password);
        }
        pthread_mutex_unlock(&conn->conn_lock);
    } else {
        chilog(TRACE, "Connection is NULL");
    }
}


/* See connection.h */
bool connection_is_registered(conn* user) {
    bool is_registered = false;
    pthread_mutex_lock(&user->conn_lock);
    if (user->nickname != NULL && user->username != NULL) {
        is_registered = true;
    }
    pthread_mutex_unlock(&user->conn_lock);
    return is_registered;
}


/* See connection.h */
int connection_set_hostname(conn* connection) {
    int s = connection->conn_socket;
    socklen_t len;
    struct sockaddr_storage addr;
    char ipstr[INET6_ADDRSTRLEN];
    int port;
    len = sizeof(addr);
    getpeername(s, (struct sockaddr*)&addr, &len);
    
    /* Determines appropriate IP (IPv4 or IPv6) */
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *) &addr;
        port = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        port = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
    }

    char name[MAX_MSG_LEN];
    int val = getnameinfo((struct sockaddr*)&addr, sizeof(addr), name, 
                            sizeof(name), NULL, 0, NI_NAMEREQD);

    if (val == 0) {
        pthread_mutex_lock(&connection->conn_lock);
        if (connection->hostname) free(connection->hostname);
        connection->hostname = strdup(name);
        if (connection->user_flag == false);
        chilog(TRACE, "Client hostname: %s", name);
        pthread_mutex_unlock(&connection->conn_lock);
    } else {
        chilog(ERROR, "Could not get hostname of connection <%s>", 
            connection->username);
        return -1;
    }
    return 0;
}


/* See connection.h */
int connection_destroy(conn* connection) {
    if (connection == NULL) {
        chilog(ERROR, "you are trying to free a NULL connection");
        return -1;
    }
    pthread_mutex_lock(&connection->conn_lock);
    if (connection->username != NULL) free(connection->username);
    if (connection->realname != NULL) free(connection->realname);
    if (connection->nickname != NULL) free(connection->nickname);
    if (connection->hostname != NULL) free(connection->hostname);
    pthread_mutex_unlock(&connection->conn_lock);

    pthread_mutex_destroy(&connection->conn_lock);
    free(connection);
    return 0;
}

#endif