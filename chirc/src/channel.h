#ifndef CHIRC_CHANNEL_H
#define CHIRC_CHANNEL_H

#include "utlist.h"
#include <pthread.h>
#include "connection.h"

/* Channel structs are in connection.h due to multiple files needing them 
 * In any function with a server_ctx *ctx parameter, it is a pointer to the
 * single server context struct.
 */

/* 
 * Helper for debugging: chilogs all channels
 * 
 * Returns: number of channels
 */
void show_channels(server_ctx *ctx);


/* 
 * Counts the number of channels present in linked list of channels in ctx
 * 
 * Returns: number of channels
 */
int count_channels(server_ctx *ctx);


/* 
 * Creates channel and adds to list of all channels 
 * 
 * Returns pointer to newly created channel
 */
chan* channel_create(server_ctx* ctx, char* name);


/* 
 * Deletes channel from list of all channels
 * 
 * Returns 0 upon success.
 */
int channel_delete(server_ctx* ctx, chan* p);


/* 
 * Adds user to channel
 * 
 * Returns pointer to connection handle 
 * that is part of the channel's linked list of users 
 */
conn_hh* channel_add_user(chan* chan, conn* user);


/* 
 * Helper log function for channel_show() for LL_FOREACH 
 *
 * conn_hh - pointer to linked list handle of users in channel
 * 
 * Returns: nothing
 */
void channel_show_ops(char* channel_name, conn_hh* conn_hh);


/*
 * Shows channel's users and channel's operators at DEBUG level
 * 
 * Returns 0 upon success.
 */
int channel_show(chan* chan);


/* 
 * Finds channel from list of all channels via ctx
 * 
 * Returns pointer to found channel, NULL if none
 */
chan* channel_find(server_ctx* ctx, char* name);


/*
 * Helper function used in list iteration; returns strcmp of
 * the channel's name and the name given to the function 
 */
int namecmp(chan* a, char* name);


/* 
 * Compares a connection and a given nickname. Helper function to find nick
 * 
 * Returns 0 if true, non-0 if not
 */
int usercmp(conn_hh* a, char* name);


/* 
 * Compares a connection and a given nickname. Helper function to find user
 * 
 * Returns 0 if true, non-0 if not
 */
int nickcmp(conn_hh* a, char* nickname);


/*
 * Sets operator for a given conn_hh in channel 
 * 
 * Returns 0 upon success.
 */
int channel_set_op(chan* p, conn_hh* conn_hh, bool op_status);


/*
 * Gets all nicknames in a given channel. Used for NICK reply.
 * 
 * Returns string with all nicks in format (e.g. ":<nick1> <nick2>")
 */
char* channel_get_nicks(server_ctx* ctx, chan* chan);


/* 
 * Finds user in channel by its username
 * 
 * Returns pointer to found user, NULL if none found
 */
conn_hh* channel_find_user(chan* p, char* username);


/* 
 * Finds user in channel by nick
 * 
 * Returns pointer to found user, NULL if none found
 */
conn_hh* channel_find_nick(chan* p, char* nickname);


/*
 * Removes user from all channels in ctx
 * 
 * Returns 0 upon success.
 */
int remove_user_all_channels(server_ctx* ctx, conn* user);


/* 
 * Removes user from channel p and removes the channel too if it becomes empty
 * 
 * Returns 0 upon succes, -1 upon failure
 */
int remove_user_from_channel(server_ctx* ctx, chan* p, conn* user);


/* 
 * Counts the number of channels in the server
 * 
 * Returns number of channels
 */
int count_channels(server_ctx *ctx);

#endif