/* 
 * channel.c - all functions related to channel interactions and creation
 *
 */

#ifndef CHIRC_CHANNEL_C
#define CHIRC_CHANNEL_C

#include "channel.h"

/* 
 * Helper function to concat nick of user to buffer
 *
 * conn_hh - pointer to LL user handle to get nick from
 * buffer - buffer to append nick to 
 * 
 * Returns: nothing
 */
void channel_concat_nicks(conn_hh* conn_hh, char* buffer);


/* See channel.h */
chan* channel_create(server_ctx* ctx, char* name) {
    chan* new_channel = (chan*) calloc(1, sizeof(chan));
    new_channel->name = strdup(name);
    new_channel->next = NULL;
    new_channel->users = NULL; // head of LL must be init to NULL
    pthread_mutex_init(&new_channel->chan_lock, NULL);

    chilog(TRACE, "Adding channel <%s> to list of channels...", name);
    LL_APPEND(ctx->channels, new_channel);
    
    return new_channel;
}


/* See channel.h */
int channel_delete(server_ctx* ctx, chan* p) {
    chilog(TRACE, "Deleting channel <%s>...", p->name);
    LL_DELETE(ctx->channels, p);
    return 0;
}

/* See channel.h */
chan* channel_find(server_ctx* ctx, char* ch_name) {
    chan* channel = NULL;
    LL_SEARCH(ctx->channels, channel, ch_name, namecmp);
    return channel;
}


/* See channel.h */
int usercmp(conn_hh* a, char* name) {
    return strcmp(a->conn->username, name);
}


/* See channel.h */
int nickcmp(conn_hh* a, char* nickname) {
    return strcmp(a->conn->nickname, nickname);
}


/* See channel.h */
conn_hh* channel_find_user(chan* p, char* username) {
    pthread_mutex_lock(&p->chan_lock);
    conn_hh* user_hh = NULL;
    LL_SEARCH(p->users, user_hh, username, usercmp);
    pthread_mutex_unlock(&p->chan_lock);
    return user_hh;
}


/* See channel.h */
conn_hh* channel_find_nick(chan* p, char* nickname) {
    pthread_mutex_lock(&p->chan_lock);
    conn_hh* user_hh = NULL;
    LL_SEARCH(p->users, user_hh, nickname, nickcmp);
    pthread_mutex_unlock(&p->chan_lock);
    return user_hh;
}


/* See channel.h */
conn_hh* channel_add_user(chan* p, conn* user) {
    /* Set up list handle for channel users LL */
    conn_hh* user_hh = (conn_hh*) calloc(1, sizeof(conn_hh));
    user_hh->conn = user;

    pthread_mutex_lock(&p->chan_lock);
    chilog(TRACE, "Adding user <%s> to channel...", user->username);
    LL_APPEND(p->users, user_hh);
    pthread_mutex_unlock(&p->chan_lock);

    return user_hh;
}


/* See channel.h */
int remove_user_from_channel(server_ctx* ctx, chan* p, conn* user) {
    chilog(TRACE, "Removing user <%s> from channel <%s>", 
                                user->username, p->name);  
    int ret = -1;
    conn_hh* found_user = channel_find_user(p, user->username);
    
    if (found_user != NULL) {
        pthread_mutex_lock(&p->chan_lock);
        LL_DELETE(p->users, found_user);
        pthread_mutex_unlock(&p->chan_lock);
        ret = 0;
    }

    /* Delete channel if empty */
    if (p->users == NULL) {
        pthread_mutex_lock(&ctx->channels_lock);
        channel_delete(ctx, p);
        pthread_mutex_lock(&ctx->channels_lock);
    }

    return ret;
}


/* See channel.h */
int remove_user_all_channels(server_ctx* ctx, conn* user) {
    chilog(DEBUG, "Removing user <%s> from all channels", user->username);
    chan* temp;
    LL_FOREACH(ctx->channels, temp) remove_user_from_channel(ctx, temp, user);
    return 0;
}


/* See channel.h */
int channel_set_op(chan* p, conn_hh* conn_hh, bool op_status) {
    
    /* Lock and change state*/
    pthread_mutex_lock(&p->chan_lock);

    chilog(TRACE, "Channel lock set set_op");
    chilog(TRACE, "Setting user <%s> as op in channel <%s>",
             conn_hh->conn->username, p->name);

    conn_hh->is_channel_operator = op_status;

    pthread_mutex_unlock(&p->chan_lock);
    chilog(TRACE, "Channel lock removed");

    return 0;
}


/* See channel.h */
int namecmp(chan* a, char* name) {
    return strcmp(a->name, name);
}


/* See channel.h */
void channel_show_ops(char* channel_name, conn_hh* conn_hh) {
    if (conn_hh->is_channel_operator) {
        chilog(TRACE, "User <%s> is a channel operator of <%s>",
         conn_hh->conn->username, channel_name);
    }
}


/* See channel.h */
int channel_show(chan* chan) {
    if (chan->name != NULL){
        chilog(DEBUG, "Showing users of channel <%s>:", chan->name);
    } else {
        chilog(DEBUG, "No name for the given channel. Shouldn't happen");
        return -1;
    }
    conn_hh* temp;
    LL_FOREACH(chan->users, temp) connection_show(temp->conn);
    LL_FOREACH(chan->users, temp) channel_show_ops(chan->name, temp);
    return 0;
}


/* See header at top of file */
void channel_concat_nicks(conn_hh* conn_hh, char* buffer) {
    char* nick = conn_hh->conn->nickname;
    sprintf(buffer, "%s%s ", buffer, nick);
}


/* See channel.h */
char* channel_get_nicks(server_ctx* ctx, chan* chan) {
    conn_hh* temp;
    char* buffer = (char *) calloc(MAX_MSG_LEN, sizeof(char));
    buffer[0] = ':';

    pthread_mutex_lock(&ctx->users_lock);
    LL_FOREACH(chan->users, temp) channel_concat_nicks(temp, buffer);
    pthread_mutex_unlock(&ctx->users_lock);


    int len = strlen(buffer);
    buffer[len-1] = '\0';
    return buffer;
}


/* see channel.h */
void show_channels(server_ctx *ctx) {
    chilog(INFO, "all channels: ---------------------------------");
    chan *channel;
    pthread_mutex_lock(&ctx->channels_lock);
    LL_FOREACH(ctx->channels, channel) {
        chilog(INFO, "Channel: %s", channel->name);
    }
    pthread_mutex_unlock(&ctx->channels_lock);

    return;
}


/* See channels.h */
int count_channels(server_ctx *ctx) {
    chan *channel = NULL;
    int count = 0;
    LL_COUNT(ctx->channels, channel, count);
    return count;
}

#endif

