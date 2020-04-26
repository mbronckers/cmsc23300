#ifndef CHIRC_MESSAGE_H
#define CHIRC_MESSAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include<stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "constants.h"
#include "connection.h"
#include "reply.h"
#include "handlers.h"

/* 
 * Function to parse & tokenize received message.
 * Sends the tokens to a helper handle_tokens which executes the message
 * 
 * msg: received message WITHOUT /r/n, etc regular null terminated
 * conn: connection (user or server)
 
 * Returns: -1 upon failure, 0 upon success
 */
int process_message(char* msg, conn* conn, server_ctx *ctx);

/*
 * Function to send reply
 * 
 * args: handle with sender info
 * fmt: format string to be sent
 * ...: any extra parameters for fmt
 *
 * Returns -1 failure, 0 success
 */
int reply(handle* args, const char* RPL_CODE, const char* fmt, ...);

/*
 * Sends message safely, does the same as send except keeps sending until
 * all of a message is sent. Taken from Beej's guide
 * 
 * socket: socket to send to, file descriptor number
 * buf: message to be sent
 * len: pointer to variable containing length, *len stores number of bytes sent
 *
 * Returns: -1 upon failure, 0 upon success. Stores bytes sent in len.
 */
int send_all(int s, char *buf, int *len);

#endif