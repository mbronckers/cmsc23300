/* 
 * constants.h - contains useful constants used in the program
 */
#pragma once 

#define MAX_MSG_LEN 513     // IRC specifies 512 + 1 for C str's /0
#define BUFFER_SIZE 1025    // Assume no more than 2 messages in buffer at once
#define MAX_PARAMS 10       // Maximum parameters to receive for our program
#define MAX_NICK_LENGTH 9   // IRC spec says 9 characters max for nick
#define MAX_QUEUED_CONNS 20 // Max backlog of connections OS will handle
#define QUIT_SIGNAL -5      // Quit message signal to handler thread to quit