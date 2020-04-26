/* 
 * message.c - all functions related to messages
 *
 * Use these functions to parse messages into tokens, send replies, or send
 * to all.
 *
 */

#ifndef CHIRC_MESSAGE_C
#define CHIRC_MESSAGE_C

#include "message.h"

/* See message.h */
int process_message(char* msg, conn* conn, server_ctx *ctx) {
    int MAX_TOKENS = MAX_PARAMS + 2;  // Prefix, command, are tokens
    char *msg_cpy = strdup(msg);
    char *save_ptr = msg_cpy; 
    char **tokens = (char**) calloc(MAX_TOKENS, sizeof(char*));
    memset(tokens, 0, MAX_TOKENS * sizeof(char *));
    char *token;
    int token_idx = 0;  

    chilog(TRACE, "Parsing message... %s", msg);

    /* Iterate over message */
    while (token = strtok_r(save_ptr, " ", &save_ptr)) { 
        
        /* Parsing long parameter correctly */
        if (token[0] == ':' && token_idx != 0) {
            tokens[token_idx] = calloc(MAX_MSG_LEN, sizeof (char));

            /* Create pointer to truncated string without ':' */
            char * truncated = NULL; 
            if(token[1] != '\r' || token[2] != '\n') {  // Nonempty last token
                truncated = token + 1;
            }

            /* Save multiple words in long parameter; 
             * save_ptr points to the character past the first space in the
             * original message.
             */
            if (save_ptr[0] != 0) {
                /* Multi word long parameter, e.g. ":Leaving now" */
                sprintf(tokens[token_idx], "%s %s", truncated, save_ptr); 
            } else {
                /* Single word long parameter, e.g. ":Leaving" */
                sprintf(tokens[token_idx], "%s", truncated); 
            }

            /* chilog(TRACE, "token: %s, size: %i", 
                        tokens[token_idx], strlen(tokens[token_idx])); */
            token_idx += 1;
            break;

        } else {
            /* Simple copying of token to tokens list */
            tokens[token_idx] = strdup(token);
        }
        
        /* chilog(TRACE, "token: %s, size: %i", tokens[token_idx], 
                strlen(tokens[token_idx])); */
        token_idx += 1;
    }

    /* Process tokens */
    int ret = handle_tokens(tokens, token_idx, conn, ctx);
    if (ret == -1) {
        chilog(ERROR, "Tokens not handled properly");
        return -1;
    }

    /* Clean up tokens; there are token_idx tokens*/
    for (int j = 0; j < token_idx; j++) {
        if (tokens[j]) free(tokens[j]);
    }
    free(tokens);
    free(msg_cpy); 

    return ret;
}


/* See message.h */
int reply(handle* args, const char* RPL_CODE, const char* fmt, ...) {
    char* msg = calloc(MAX_MSG_LEN, sizeof(char));
    int socket = args->conn->conn_socket;

    if (!socket) {
        chilog(ERROR, "No socket for reply");
        return -1;
    }
     
    /* Dealing with unknown amount of parameters by using 
     * variable argument list and c-defined macros. */
    va_list l;
    va_start(l, fmt);
    
    char* text = calloc(MAX_MSG_LEN, sizeof(char));  // Constructed message
    vsprintf(text, fmt, l);
    va_end(l);
    
    /* Creating message */
    char *nickname = "*";
    
    /* Read nick and send data*/
    pthread_mutex_lock(&args->conn->conn_lock);
    if (args->conn->nickname != NULL) {
        nickname = args->conn->nickname;
    }
    sprintf(msg, 
            ":%s %s %s %s\r\n",
            args->conn->hostname,
            RPL_CODE, 
            nickname,
            text);

    chilog(TRACE, "Sending message: %s", msg);

    int bytes = strlen(msg);
    if (send_all(socket, msg, &bytes) == -1) {
        chilog(ERROR, "Socket send_all failed, socket %s message %s",
                                                                 socket, msg);
        pthread_mutex_unlock(&args->conn->conn_lock);
        return -1;
    }

    pthread_mutex_unlock(&args->conn->conn_lock);

    free(text);
    free(msg);

    return 0;
}


/* See message.h */
int send_all(int socket, char *buf, int *len) {
    int total = 0;
    int bytes_left = *len;
    int n;

    while (total < *len) {
        n = send(socket, buf + total, bytes_left, 0);
        if (n == -1) {
            break;
        }
        total += n;
        bytes_left -= n;
    }

    *len = total;

    return (n == -1 ? -1 : 0); 
} 
#endif