/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* When we want to debug and not deal with random initial sequence numbers, 
 * compile code with this set to false. This will use DEBUG_ISS as the ISS */
const static bool USE_RANDOM_ISS = true;
const static uint32_t DEBUG_ISS = 1000;

/* Probe segment 1 byte of data */
const static int PROBE_LEN = 1;  

/* These have to be 0 and 1 because we just have 2 timers which are IDed 1,2 */
const static int RETRANSMISSION_TIMER_ID = 0;
const static int PERSIST_TIMER_ID = 1;


/* struct for callback arguments to pass si & entry to retransmission_callback */
typedef struct callback_info {
    serverinfo_t* si;
    chisocketentry_t *entry;
} callback_info_t;

/*
 * Handles packet arrival events in ANY TCP state
 * 
 * Parameters are the same as all the other tcp state handling functions
 * This function reads the tcp_state directly from entry->tcp_state;
 * 
 * event should equal PACKET_ARRIVAL; function returns -1 otherwise
 * Returns -1 on error, 0 on success.
 */
int handle_packet_arrival(serverinfo_t *si, chisocketentry_t *entry, 
                            tcp_event_type_t event);

/*
 * Helper function for sending data from send buffer:
 * Checks the send buffer and sees if any data can be sent out;
 * Returns total number of bytes of data sent out (which can be over multiple
 *                                                  segments)
 */
int process_send_buffer(serverinfo_t *si, chisocketentry_t *entry);


/* Update send window size to new receiver's window size if it changed 
 * Effective window size as informed by the incoming packet 
 * 
 * inc_packet - pointer to incoming tcp packet that triggered window change
 * entry      - pointer to the socket's TCB
 * si         - pointer to serverinfo
 * 
 * returns: 0 always 
 */
int process_window_change(tcp_packet_t *inc_packet, chisocketentry_t *entry, 
                            serverinfo_t *si);


/* 
 * Sends an ACK packet with specified seq, ack_seq, win; no payload. 
 * Optional FIN can be added with fin_flag = true
 * 
 * seq & ack_seq & win - HOST endianness
 * seq - sequence number of the packet to be sent
 * ack_seq - seq number of next packet to be acknowledged from other side
 * win - my receive window size
 * fin_flag - whether or not to also send a FIN along with the ACK
 * 
 * si & entry - needed for chitcpd_send_tcp_packet()
 * 
 * Returns 0 always
 */
int send_ack(tcp_seq seq, tcp_seq ack_seq, uint16_t win, bool fin_flag, 
            serverinfo_t *si, chisocketentry_t *entry);


/* 
 * Sends an FIN packet with specified seq, ack_seq, win 
 * 
 * si & entry - needed for chitcpd_send_tcp_packet()
 * 
 * Returns 0 always
 */
int send_fin(serverinfo_t *si, chisocketentry_t *entry);


/* 
 * Checks if a TCP connection teardown has been requested and acts accordingly.
 * Only sends out FIN if send buffer empty and all packets have been ack'd.
 * Updates tcp_data to NEXT_STATE to advance in teardown.
 *
 * Is called only in ESTABLISHED or in CLOSE_WAIT (the only states that
 * initiate teardown) at any packet_arrival or application_close event, since 
 * after requesting an application_close you cannot send any additional segments
 *
 * si & entry - needed for tcp_data & send_fin
 * 
 * Returns 0 always, but warns if state could not be updated.
 */
int check_close(serverinfo_t *si, chisocketentry_t *entry);


/*
 * Callback function that generates a TIMEOUT_RTX event upon RT timer expiration
 *
 * si & entry - needed for chitcp_timeout() generation
 *
 * Returns nothing
 */
void retransmission_callback(struct multi_timer *mt, struct single_timer *timer, 
                            void* callback_args);

/*
 * Callback function that generates a TIMEOUT_PST event upon persist
 * timer expiration
 *
 * si & entry - needed for chitcp_timeout() generation
 *
 * Returns nothing
 */
void persist_callback(struct multi_timer *mt, struct single_timer *timer, 
                            void* callback_args);



/*
 * Sends packet wrapped with proper retransmission set-up / initialization
 * If the packet specified is already in the RTQ, which is specified by the 
 * flag append_to_RTQ, then the packet specified gets
 * its send_time updated and its position in the RTQ doesn't change
 *
 * packet - to be sent
 * si & entry - usual suspects
 * append_to_RTQ - When True, appends packet to RTQ. Set this to false when 
                   we retransmit a packet that is already in RTQ.
 *
 * Returns nothing // TODO change to return value based on success
 */
void send_packet(serverinfo_t *si, chisocketentry_t *entry, 
                tcp_packet_t *packet, bool append_to_RTQ);


/* 
 * Processes retransmission queue upon receiving acks.
 *
 * resets/cancels timers and removes packets from RTQ
 * 
 * inc_packet - incoming ACK
 * si & entry - usual suspects
 *
 * Returns CHITCP_OK
 */
int check_rtq(serverinfo_t *si, chisocketentry_t *entry, tcp_packet_t *inc_packet);


/*
 * Handles retransmission of packets & reset of timer after a TIMEOUT_RTX event
 *
 * Follows p. 4 of RFC 793.
 *
 * Ignores 5.7 per Project 2 specification
 * 
 * Returns: CHITCP_OK
 */
int handle_timeout(serverinfo_t *si, chisocketentry_t *entry);


/*
 * Handles persist timer timeout
 * If send buffer is empty, then reset timer to RTO seconds
 * If send buffer has stuff (but window is still 0 since persist timer hit its
 * timeout, then we send a probe segment of 1 byte
 *
 * Ignores 5.7 per Project 2 specification
 * 
 * Returns: CHITCP_OK
 */
int handle_persist_timeout(serverinfo_t *si, chisocketentry_t *entry);


/*
 * Implements the accountability test for incoming segments
 *
 * Follows p. 69 of RFC 793.
 *
 * Ignores RST and security checks
 *
 * If modify_state is true, then it'll free the incoming packet
 * and send a acknowledgement of the last acceptable packet (not this one)
 * Otherwise, it just returns a boolean
 * 
 * Returns: 0 upon success, -1 upon failure.
 */
int acceptable(tcp_packet_t *inc_packet, serverinfo_t *si, 
                chisocketentry_t *entry, bool modify_state);


/* 
 * Comparator function for DD_INSERT_INORDER for packets in OOD
 *
 * Returns:
 *     -1 : packet1 goes before packet2
 *      0 : packet1 equals packet2; should not happen
 *      1 : packet1 goes after packet2
 */
int compare_packets(rtq_packet_list_t* t1, rtq_packet_list_t* t2);


/*
 * rtq_packet_list_insert - Adds a packet to the tail of a RTQ list
 *                   with time_sent specified. Inserts the packet in order
 *                   of increasing sequence number for organizational purposes
 *
 * pl: Pointer to head pointer (if the head pointer was initially NULL, this
 *     function will update it to point to the node that was just added).
 *
 * time_sent: struct timespec to indicate time of packet sent
 *
 * packet: Pointer to packet to be added.
 *
 * Returns: Always returns CHITCP_OK.
 */
int rtq_packet_list_insert(rtq_packet_list_t **pl, tcp_packet_t *packet, 
                            struct timespec *time_sent);


/* Helper functions for RTQ packet list. It would make more sense in my
 * opinion to just add a field to tcp_packet_list and make the RTQ packet list
 * an instance of that, which is what we originally did. 
 * 
 * However, this would
 * not be compatible with the autograder (since it just loads multitimer and 
 * the tcp files) so we need copies of the chitcp helper functions for our
 * RTQ that do the same thing and essentially have the same code
 * 
 * These do EXACTLY the same thing as their tcp packet counterparts; thus
 * there is no point repeating the documentation in packet.h verbatim here
/*   


/* See corresponding functions in packet.h. Does the exact same behavior */
int rtq_packet_list_size(rtq_packet_list_t *pl);
int rtq_packet_list_destroy(rtq_packet_list_t **pl);


/* Frees a RTQ packet and returns 0 */
int free_rtq_packet(rtq_packet_list_t *pac);


/* Returns total bytes of data contained in packet, with SYN/FIN being 1 */
uint32_t total_packet_content(tcp_packet_t *packet);


/* See above declaration */
void send_packet(serverinfo_t *si, chisocketentry_t *entry, 
                    tcp_packet_t *packet, bool append_to_RTQ) {
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    /* Get time sent of packet */
    struct timespec *time_sent = calloc(1, sizeof(struct timespec));
    clock_gettime(CLOCK_REALTIME, time_sent);

    /* If new packet, add packet to end of retransmission queue if its
     * more than just a naked ACK with 0 bytes of data
     */
    bool naked_ack; 
    naked_ack = (total_packet_content(packet) == 0);
    if (append_to_RTQ) {
        if (!naked_ack) {
            rtq_packet_list_insert(&(tcp_data->RTQ), packet, time_sent);
        } 
    } 

    /* If not, find existing packet in RTQ and update its send time - 
     * needed for RTQ calculations */
    else {
        rtq_packet_list_t *rtq_packet;
        DL_FOREACH(tcp_data->RTQ, rtq_packet) {
            if (rtq_packet->packet == packet) {
                
                /* Free old time sent and update it to current time */
                free(rtq_packet->time_sent);
                rtq_packet->time_sent = time_sent;
                break;

            }
        }
    }

    
    /* Sending packet */
    chitcpd_send_tcp_packet(si, entry, packet);

    // Don't do any retransmission for naked ACKs; let other side resend
    if (naked_ack) return;

    /* Set RT timer & timer name if not timer is not running per RFC */
    single_timer_t *temp;
    mt_get_timer_by_id(tcp_data->mt, RETRANSMISSION_TIMER_ID, &temp);
    
    if (!temp->active && !naked_ack) {
        mt_set_timer(tcp_data->mt, RETRANSMISSION_TIMER_ID, 
                     tcp_data->RTO, tcp_data->retransmission_callback, 
                     tcp_data->callback_args);
        mt_set_timer_name(tcp_data->mt, RETRANSMISSION_TIMER_ID,
                            "Retransmission");        
    }

}


/* See above declaration */
void retransmission_callback(struct multi_timer *mt, struct single_timer *timer, 
                            void* callback_args) {
    callback_info_t *args = (callback_info_t *) callback_args;
    chitcpd_timeout(args->si, args->entry, RETRANSMISSION);
}

/* See above declaration */
void persist_callback(struct multi_timer *mt, struct single_timer *timer, 
                            void* callback_args) {
    callback_info_t *args = (callback_info_t *) callback_args;
    chitcpd_timeout(args->si, args->entry, PERSIST);
}


/* See above declaration */
int process_send_buffer(serverinfo_t *si, chisocketentry_t *entry) {
    
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    int bytes_sent = 0;
    
    /* Logging */
    chilog(DEBUG, "SEND WINDOW SIZE %d %d", 
                                    tcp_data->SND_WND, 
                                    circular_buffer_count(&tcp_data->send));

    /* Keep sending out data until we send all data
       or until we fill advertised receiver's window */
    while (tcp_data->SND_UNA + tcp_data->SND_WND > tcp_data->SND_NXT
           && circular_buffer_count(&tcp_data->send) > 0 &&
           !tcp_data->probe_seg_active) { 
        
        /* Select a payload of min(MSS, payload_len),
           where payload_len = min(bytes in send buffer, send window) */
        int effective_window = tcp_data->SND_UNA + tcp_data->SND_WND - 
                                tcp_data->SND_NXT;
        int send_size = circular_buffer_count(&tcp_data->send);
        uint16_t payload_len = MIN(send_size, effective_window);
        payload_len = MIN(payload_len, TCP_MSS);
        
        /* Try to read payload_len bytes from the send buffer */
        tcp_packet_t *packet = (tcp_packet_t*) calloc(1, sizeof(tcp_packet_t));
        uint8_t *payload = calloc(1, payload_len);

        /* Update payload length in case we can't read payload_len bytes 
         * This shouldn't happen, since payload_len should be <=
         * num of bytes in the send buffer */
        payload_len = circular_buffer_read(&tcp_data->send, payload, 
                                            payload_len, true);
        
        int packetlen = chitcpd_tcp_packet_create(  
                        entry, packet, payload, payload_len);

        tcphdr_t *header = TCP_PACKET_HEADER(packet);

        header->ack = 1;
        /* NOTE: Following fields are in NETWORK byte order (big-endian) */
        header->seq = htonl(tcp_data->SND_NXT);
        header->ack_seq = htonl(tcp_data->RCV_NXT);
        header->win = htons(tcp_data->RCV_WND);

        /* Logging */
        chilog(TRACE, "Sending segmentized packet in SEND with payload size %d", 
                        payload_len);

        chilog_tcp(DEBUG, packet, LOG_OUTBOUND);
        
        /* Sending packet w/ retransmission */
        send_packet(si, entry, packet, true);
        bytes_sent += payload_len;

        /* Update send window size & SND_NXT by the payload_len sent */
        tcp_data->SND_NXT += payload_len;
    }
    return bytes_sent;
}


/* See above declaration */
int process_window_change(tcp_packet_t *inc_packet, chisocketentry_t *entry, 
                            serverinfo_t *si)
{
    
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    
     /* Receiving an advertised window of 0 bytes. Set persist timer */
    single_timer_t *persist;
    mt_get_timer_by_id(tcp_data->mt, PERSIST_TIMER_ID, &persist);

    if (SEG_WND(inc_packet) == 0) {
        chilog(DEBUG, "Zero Window Advertised. Persist Timer Activated!");
        
        if (!persist->active) {
            chilog(DEBUG, "Persist timer not active; setting it for packet:");
            chilog_tcp(DEBUG, inc_packet, LOG_OUTBOUND);
            
            mt_chilog(DEBUG, tcp_data->mt, false);
            mt_set_timer(tcp_data->mt, PERSIST_TIMER_ID, 
                        tcp_data->RTO, tcp_data->persist_callback, 
                        tcp_data->callback_args);
            mt_set_timer_name(tcp_data->mt, PERSIST_TIMER_ID, 
                            "Persist");
        
        }

    } else {
        /* Update window and snd_una */
        tcp_data->SND_WND = SEG_WND(inc_packet);
        
        /* Probe segment was received since window changed */
        if (tcp_data->probe_seg_active) {
            chilog(DEBUG, "Probe segment received so nullifying it");
            tcp_data->probe_seg_active = false;
        }
    
        /* Update send buffer since snd_wnd is updated */
        process_send_buffer(si, entry);
    
    }

    return 0;
}

/* See above declaration */
int send_ack(tcp_seq seq, tcp_seq ack_seq, uint16_t win, bool fin_flag, 
    serverinfo_t *si, chisocketentry_t *entry) {

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    /* Create return packet, fill it with appropriate info, send it */
    tcp_packet_t *return_packet = calloc(1, sizeof(tcp_packet_t));
    uint8_t* payload = NULL;
    uint16_t payload_len = 0;

    int packetlen = chitcpd_tcp_packet_create(
                    entry, return_packet, payload, payload_len);

    tcphdr_t *return_header = TCP_PACKET_HEADER(return_packet);

    if (fin_flag) return_header->fin = 1;

    return_header->ack = 1;       
    /* Following fields are in NETWORK byte order (big-endian) */
    return_header->seq = htonl(seq);
    return_header->ack_seq = htonl(ack_seq);
    return_header->win = htons(win);

    /* Logging */
    if (fin_flag) chilog(TRACE, "Sending return FIN & ACK:");
    else chilog(TRACE, "Sending return ACK:");
    chilog_tcp(TRACE, return_packet, LOG_OUTBOUND);
    /*
    // Fins need to be retransmitted, so send_packet to add packet to RTQ 
    if (fin_flag) send_packet(si, entry, return_packet, true);
    
    // Don't want to retransmit acks, so manually send 
    else chitcpd_send_tcp_packet(si, entry, return_packet);
    */
    send_packet(si, entry, return_packet, true);

    /* Change state to appropriate state */
    return 0;
}

/* See above declaration */
int send_fin(serverinfo_t *si, chisocketentry_t *entry) {
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    return send_ack(tcp_data->SND_NXT, tcp_data->RCV_NXT, tcp_data->RCV_WND, 
                        true, si, entry);
}

/* See above declaration */
int check_close(serverinfo_t *si, chisocketentry_t *entry) {
    
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    if (tcp_data->closing) {

        if (circular_buffer_count(&tcp_data->send) == 0 &&
            tcp_data->SND_UNA == tcp_data->SND_NXT) {
            
            /* Send FIN */
            send_fin(si, entry);

            /* Update state to next state */
            if (tcp_data->NEXT_STATE != entry->tcp_state) {
                chitcpd_update_tcp_state(si, entry, tcp_data->NEXT_STATE);
                
                tcp_data->closing = false;

                return 0;
            }

            chilog(WARNING, "Could not update to NEXT_STATE");
        }

        chilog(DEBUG, "Send buffer not empty and/or UNA != NXT");

    }

    return 0;
}

/* See above declaration */
int check_rtq(serverinfo_t *si, chisocketentry_t *entry, 
    tcp_packet_t *inc_packet) {

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    
    /* Debug Logging */
    chilog(DEBUG, "Packets in RTQ before cleanup: <%i>", 
                        rtq_packet_list_size(tcp_data->RTQ));
                        
    int i = 0;
    rtq_packet_list_t* elt;
    rtq_packet_list_t* temp;

    /* Get current time to calculate packet RTTs */
    struct timespec now;
    struct timespec diff;
    clock_gettime(CLOCK_REALTIME, &now);

    /* Iterate over RTQ */
    DL_FOREACH_SAFE(tcp_data->RTQ, elt, temp) {
    
        /* Incoming ack contains bytes sent from this packet in RTQ */
        if (SEG_ACK(inc_packet) >= 
            (SEG_SEQ(elt->packet) + total_packet_content(elt->packet))) {
            
            /* Time it took for packet to arrive */
            timespec_subtract(&diff, &now, elt->time_sent);

            /* Packet round trip time in nanoseconds */
            uint64_t packet_rtt = diff.tv_sec * SECOND + diff.tv_nsec;

            // TODO do we need this long comment? don't think so
            /* Update RTT: Uses algorithm specified in 
               https://tools.ietf.org/html/rfc6298#section-2
               Values of following constants given in the RFC */
            
            int K = 4;             // k = 4 specified in RFC
            int GRANULARITY = 50;  // 50 ms granularity per project guide
            float ALPHA = 0.125;
            float BETA = 0.25;
            uint64_t MIN_RTT = 200*MILLISECOND;

            if (tcp_data->SRTT == 0) {  
                tcp_data->SRTT = packet_rtt;
                tcp_data->RTTVAR = packet_rtt / 2;
                tcp_data->RTO = tcp_data->SRTT + MAX(GRANULARITY * MILLISECOND, 
                                                        K * tcp_data->RTTVAR);
            } else {
                tcp_data->RTTVAR = ((1.0 - BETA) * tcp_data->RTTVAR) + 
                                    BETA * abs(tcp_data->SRTT - packet_rtt);
                tcp_data->SRTT = ((1.0 - ALPHA) * tcp_data->SRTT) + 
                                    ALPHA * packet_rtt;
            }
            

            tcp_data->RTO = tcp_data->SRTT + MAX(GRANULARITY, 
                                                 K * tcp_data->RTTVAR);

            /* Make RTO at least 200 ms as specified in project guide.
             * This deviates from the 1 second suggested by TCP */
            if (tcp_data->RTO < MIN_RTT) tcp_data->RTO = MIN_RTT;

            /* TODO We do a max RTO of 10 seconds so lots of dropped packets
             * don't time us out */
            uint64_t MAX_RTT = 10 * SECOND;
            if (tcp_data->RTO > MAX_RTT) tcp_data->RTO = MAX_RTT;
            
            /* Remove packet from queue */
            DL_DELETE(tcp_data->RTQ, elt);
            free_rtq_packet(elt);

            /* Restart retransmission timer to current RTO */
            mt_cancel_timer(tcp_data->mt, RETRANSMISSION_TIMER_ID);
            mt_set_timer(tcp_data->mt, RETRANSMISSION_TIMER_ID, tcp_data->RTO,
                         tcp_data->retransmission_callback, 
                         tcp_data->callback_args);

        }

        /* Stop timer if RTQ empty */
        if (rtq_packet_list_size(tcp_data->RTQ) == 0) {
            mt_cancel_timer(tcp_data->mt, RETRANSMISSION_TIMER_ID);
        }

    }

    /* Log RTQ */
    chilog(DEBUG, "Packets in RTQ after cleanup: <%i>", 
                    rtq_packet_list_size(tcp_data->RTQ));

    return CHITCP_OK;
}


/* See declaration above */
int compare_packets(rtq_packet_list_t* t1, rtq_packet_list_t* t2) {
    
    uint32_t seq_t1 = SEG_SEQ(t1->packet);
    uint32_t seq_t2 = SEG_SEQ(t2->packet);
    
    if (seq_t1 < seq_t2) return -1;
    else if (seq_t1 = seq_t2) return 0;
    else if (seq_t2 > seq_t1) return 1;

    return 0;
}

/* See above declaration */
int acceptable(tcp_packet_t *inc_packet, serverinfo_t *si, 
                chisocketentry_t *entry, bool modify_state)
{

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcphdr_t *inc_header = TCP_PACKET_HEADER(inc_packet);
    
    /* Check the segment seq number for duplicate segments*/
    bool acceptable = false;  
    uint32_t recv_boundary = tcp_data->RCV_NXT + tcp_data->RCV_WND; 
    if (SEG_LEN(inc_packet) == 0) { 
        if (tcp_data->RCV_WND == 0) {
            acceptable = (SEG_SEQ(inc_packet) == tcp_data->RCV_NXT);
        } else {
            acceptable = tcp_data->RCV_NXT <= SEG_SEQ(inc_packet) && 
                        SEG_SEQ(inc_packet) < recv_boundary;
        }
    } else if (tcp_data->RCV_WND == 0) {
        acceptable = false;
        chilog(INFO, "Receive window size 0, packet_arrival");
    } else {
        bool cond1 = tcp_data->RCV_NXT <= SEG_SEQ(inc_packet) && 
                        SEG_SEQ(inc_packet) < recv_boundary;
        

        /* position of last byte of the incoming packet */
        uint32_t pos = SEG_SEQ(inc_packet) + SEG_LEN(inc_packet) - 1;
        bool cond2 = tcp_data->RCV_NXT <= pos && pos < recv_boundary;
        acceptable = cond1 || cond2; 

    }
    if (!acceptable) {  
        /* Send acknowledgement as specified on page 69, 
         * then drop the segment (already done earlier) */
        chilog(WARNING, "Incoming segment is not acceptable");
        
        if (modify_state) {
            send_ack(tcp_data->SND_NXT, tcp_data->RCV_NXT, tcp_data->RCV_WND, 
                        false, si, entry);

            if (inc_packet) chitcp_tcp_packet_free(inc_packet);
        }

        return -1;
    }

    /* Ignore RST bit & security stuff */

    /* 4: Check the SYN bit */
    if (inc_header->syn) {
        chilog(ERROR, "Should not receive SYN again in state %s", 
                entry->tcp_state);
        return -1;
    }

    /* Check for presence of ACK */
    if (!inc_header->ack) {
        chilog(ERROR, "No ACK on received packet while in state %s", 
                entry->tcp_state);
        return -1;
    }

    return 0;
}

int handle_timeout(serverinfo_t *si, chisocketentry_t *entry) {
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    rtq_packet_list_t* temp;
    int i = 0;
    uint32_t start_seq;

    /* Update RTO to 2 * RTO per RFC */
    tcp_data->RTO = tcp_data->RTO * 2;
    chilog(DEBUG, "Updated RTO");

    single_timer_t *timer;
    mt_get_timer_by_id(tcp_data->mt, RETRANSMISSION_TIMER_ID, &timer);
    
    /* Cancel if active (shouldn't be but safety) */
    if (timer->active) {
        /* Restart timer to RTO if it's still running (Shouldn't happen...) */
        chilog(WARNING, "RTQ timer still active on a timeout... Timers shown:.");
        mt_chilog(WARNING, tcp_data->mt, false);
        mt_cancel_timer(tcp_data->mt,
                                      RETRANSMISSION_TIMER_ID);
        
        mt_set_timer(tcp_data->mt, RETRANSMISSION_TIMER_ID, tcp_data->RTO,
                    tcp_data->retransmission_callback, 
                    tcp_data->callback_args);
    }

    /* Retransmit earliest unack'ed segment */
    DL_FOREACH(tcp_data->RTQ, temp) {
            
        /* Earliest unack'ed byte is less than packet's initial byte */
        if (tcp_data->SND_UNA <= SEG_SEQ(temp->packet))  {
            
            /* Debugging logging*/
            i++;
            if (i == 1) start_seq = SEG_SEQ(temp->packet);
            send_packet(si, entry, temp->packet, false);

        }
    }

    chilog(INFO, "Re-sent <%i> packet(s) starting at [%u] and reset timer", 
                        i, start_seq);
    return CHITCP_OK;
}


/* See above declaration */
int handle_persist_timeout(serverinfo_t *si, chisocketentry_t *entry) {

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    /* We shouldn't have any unacked data at this point; otherwise, the 
        * other side should acknowledge that data which would give us an 
        * updated window. If there is unacked data, don't send probe seg*/

    /* There is data to send. Send a probe segment of 1 byte, w/o RTQing it */
    if (circular_buffer_count(&tcp_data->send) > 0 || 
            tcp_data->probe_seg_active) 
        {

        mt_set_timer(tcp_data->mt, PERSIST_TIMER_ID, 
            tcp_data->RTO, tcp_data->persist_callback, 
            tcp_data->callback_args);

        uint8_t *payload = calloc(PROBE_LEN, sizeof(uint8_t));
        tcp_packet_t *packet = calloc(1, sizeof(tcp_packet_t));

        chilog(INFO, "Persist timer reset. Still outbound data");
        if (!tcp_data->probe_seg_active) { // Remove byte from buffer, send it
            tcp_data->probe_seg_active = true;
            /* Probe segment hasn't been removed from buffer. Remove it */
            int nbytes_read = circular_buffer_read(&tcp_data->send, payload, 
                                                PROBE_LEN, true);
            memcpy(&tcp_data->probe_data, payload, PROBE_LEN);
            tcp_data->SND_NXT += PROBE_LEN;
        } 
        
        memcpy(payload, &tcp_data->probe_data, PROBE_LEN);
        int packetlen = chitcpd_tcp_packet_create(entry, packet, 
                                                    payload, PROBE_LEN);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        
        /* -1 are because we incremented SND_NXT and SND_WND preemptively */
        header->seq = chitcp_htonl(tcp_data->SND_NXT - PROBE_LEN);
        header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        header->win = chitcp_htons(tcp_data->RCV_WND);  
        header->ack = 1;      
        chitcpd_send_tcp_packet(si, entry, packet);
        chilog(DEBUG, "Persist packet sent");
        chilog_tcp(DEBUG, packet, LOG_OUTBOUND);
        return 0; 
    } else {  // There is no data to send but still 0 window. 
              // Reset timer to RTO seconds 
        mt_set_timer(tcp_data->mt, PERSIST_TIMER_ID, 
                        tcp_data->RTO, tcp_data->persist_callback, 
                        tcp_data->callback_args);
    }

    return 0;
}


/* See above declaration */
int handle_packet_arrival(serverinfo_t *si, chisocketentry_t *entry, 
                            tcp_event_type_t event)
{

    if (event != PACKET_ARRIVAL) {
        chilog(ERROR, "Packet arrival handler called for wrong event");
    }

    /* Find incoming packet in pending packet queue */
    tcp_packet_t *inc_packet = NULL;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    if (tcp_data->pending_packets) {
        pthread_mutex_lock(&tcp_data->lock_pending_packets);
        inc_packet = tcp_data->pending_packets->packet; // FIFO order 
        chitcp_packet_list_pop_head(&tcp_data->pending_packets);
        pthread_mutex_unlock(&tcp_data->lock_pending_packets);
    } else {
        chilog(ERROR, "No pending packets in packet arrival...");
        return -1;
    }

    /* Logging incoming packet info */
    chilog(TRACE, "Incoming packet information: ");
    chilog_tcp(TRACE, inc_packet, LOG_INBOUND);

    bool send_return_packet = false;
    tcphdr_t *inc_header = TCP_PACKET_HEADER(inc_packet);

    /* Information about the return packet that we fill as necessary*/
    uint16_t return_syn = 0, return_ack = 0;
    tcp_seq return_seq = chitcp_htonl(tcp_data->SND_NXT);
    tcp_seq return_ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    uint16_t return_win = chitcp_htons(tcp_data->RCV_WND);
    uint8_t* payload = NULL;
    uint16_t payload_len = 0;

    /* New state to update to */
    tcp_state_t NEW_STATE = entry->tcp_state;

    /* Process RTQ based on incoming packet */
    check_rtq(si, entry, inc_packet);

    if (entry->tcp_state == LISTEN) {
        /* No need to worry about checking the RST flags */
        
        /* Incoming packet shouldn't have ACK since we're in LISTEN state */
        if (inc_header->ack) {
            chilog(ERROR, "Incoming packet in LISTEN state has ACK");
            return -1;
        }

        /* Incoming packet needs SYN flag set to init 3-way hshake */
        if (!inc_header->syn) {
            chilog(ERROR, "No SYN bit received for initializing 3-way hshake");
            return -1;
        }

        /* Update our TCB info */
        tcp_data->IRS = SEG_SEQ(inc_packet);
        circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
        
        tcp_data->RCV_NXT = SEG_SEQ(inc_packet) + 1;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        
        tcp_data->SND_NXT = tcp_data->ISS + 1;
        tcp_data->SND_UNA = tcp_data->ISS;
        process_window_change(inc_packet, entry, si);

        /* Update return packet info */
        send_return_packet = true;
        return_syn = 1;
        return_ack = 1;       
        return_seq = chitcp_htonl(tcp_data->ISS); 
        return_ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        return_win = chitcp_htons(tcp_data->RCV_WND);
        NEW_STATE = SYN_RCVD;

        /* Proceed to end of function which sends the return packet */

    } else if (entry->tcp_state == SYN_SENT) {
        
        /* See pages 66-68 of RFC for detailed logic */
        if (inc_header->ack) {
            if (SEG_ACK(inc_packet) <= tcp_data->ISS || 
                SEG_ACK(inc_packet) > tcp_data->SND_NXT) {
                /* Supposed to send a reset, but we don't support that */
                chilog(ERROR, "Supposed to send a reset; SYN_SENT case 1");
                chilog_tcp(DEBUG, inc_packet, LOG_INBOUND);
                return -1;
            } else if (!(tcp_data->SND_UNA <= SEG_ACK(inc_packet) && 
                        SEG_ACK(inc_packet) <= tcp_data->SND_NXT)) {
                chilog(ERROR, "ACK is not acceptable; SYN_SENT state");
                return -1;
            } 
        }

        /* Skip RST checking and security checking directly to SYN checking */
        if (!inc_header->syn) {
            chilog(ERROR, "No SYN bit found in SYN_SENT state rcvd packet");
            return -1;
        }

        /* ACK & SYN good; Update our TCB info */
        tcp_data->IRS = SEG_SEQ(inc_packet);
        circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
        tcp_data->RCV_NXT = SEG_SEQ(inc_packet) + 1;

        if (inc_header->ack) {
            tcp_data->SND_UNA = SEG_ACK(inc_packet);
            process_window_change(inc_packet, entry, si);
            chilog(WARNING, "No ack in SYN_SENT received packet header");
        }

        /* Update TCB info */
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        tcp_data->SND_NXT = tcp_data->ISS + 1;

        /* Prepare appropriate response (either ACK or SYN, ACK seg) */
        send_return_packet = true;
        return_ack = 1;
        return_ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
        if (tcp_data->SND_UNA > tcp_data->ISS) {  // Our SYN has been ACKed
            return_seq = chitcp_htonl(tcp_data->SND_NXT);
            NEW_STATE = ESTABLISHED;
        } else {
            return_syn = 1;
            return_seq = chitcp_htonl(tcp_data->ISS);
            NEW_STATE = SYN_RCVD;
        }

    } else if (entry->tcp_state == LAST_ACK) {

        /* FIN received in LAST_ACK state, p 75 */
        if (inc_header->fin && inc_header->ack) {
            // FIN received means stay in LAST_ACK state and ack their FIN.
            return_ack = 1;
            send_return_packet = true;
        } else if (inc_header->ack) {
            /* only thing that can arrive is an ACK of our FIN (since other is
               in FIN_WAIT_1/2 */
            return_ack = 1;
            send_return_packet = true;
            // Socket layer handles TCB deletion
            NEW_STATE = CLOSED;

        }
    
    } else if (entry->tcp_state == SYN_RCVD) { // Pages 68-75 of RFC
        
        if (acceptable(inc_packet, si, entry, true) == -1) {
            return -1;
        }

        if (tcp_data->SND_UNA <= SEG_ACK(inc_packet) && 
            SEG_ACK(inc_packet) <= tcp_data->SND_NXT) {
            
            /* Updating TCB info */
            tcp_data->SND_UNA = SEG_ACK(inc_packet);
            tcp_data->RCV_NXT = SEG_SEQ(inc_packet);
            process_window_change(inc_packet, entry, si);

            /* Update header info */
            NEW_STATE = ESTABLISHED;
            return_ack = 1;
            return_seq = chitcp_htonl(tcp_data->SND_NXT);
            return_ack_seq = chitcp_htonl(tcp_data->RCV_NXT);

            /* No ACK to be sent, just continue */
            send_return_packet = false;
        }

        /* Received <FIN> message */
        if (inc_header->fin) {
            return_ack = 1;
            send_return_packet = true;
            
            /* No need to process any payload since not ESTABLISHED state */

            NEW_STATE = CLOSE_WAIT;
        }

    } else if (true) {  // remaining states (Pages 68-75 of RFC)
                        /* 
                        SYN-RECEIVED STATE (Implemented above, not here)
                        ESTABLISHED STATE
                        FIN-WAIT-1 STATE
                        FIN-WAIT-2 STATE
                        CLOSE-WAIT STATE
                        CLOSING STATE
                        LAST-ACK STATE
                        TIME-WAIT STATE
                        */
        
        /* Acceptability test for incoming segment (p. 69) */
        if (acceptable(inc_packet, si, entry, true) == -1) return -1;

        /* Add to OOD if applicable and update RCV.WND */
        if (SEG_SEQ(inc_packet) > tcp_data->RCV_NXT && inc_header->ack) {
            
            /* Logging of OOD packet arrival */
            chilog(WARNING, "Incoming packet SEQ [%u] > RCV_NXT [%u]",
                             SEG_SEQ(inc_packet), tcp_data->RCV_NXT);
            bool already_queued = false;
            
            /* If already in OOD, do not re-add */
            rtq_packet_list_t *ood_packet;
            for (ood_packet = tcp_data->OOD; ood_packet != NULL; 
                ood_packet = ood_packet->next) {
                if (ood_packet->packet == inc_packet) {
                    /* Free old time sent and update it to current time */
                    already_queued = true;
                    break;
                }
            }
            
            /* Insert in order if packet is out of order but valid */
            if (!already_queued) {
                rtq_packet_list_insert(&tcp_data->OOD, inc_packet, NULL);
            }
            
            /*  Update RCV.WND availability */
            tcp_data->RCV_WND -= TCP_PAYLOAD_LEN(inc_packet);

            return 0;
        }

        /* Received an <ACK> with the message */
        if (inc_header->ack) {
            
            /* Received ack is new information; update send window */
            if (tcp_data->SND_UNA < SEG_ACK(inc_packet)) {
                
                /* Update send window */
                tcp_data->SND_UNA = SEG_ACK(inc_packet);
                process_window_change(inc_packet, entry, si);
                
            }
            
            /* ACK is for something not yet sent, drop packet & send ACK */
            else if (SEG_ACK(inc_packet) > tcp_data->SND_NXT) {
                chilog(ERROR, "Incoming segment is ACK something unsent");
                
                send_ack(tcp_data->SND_NXT, tcp_data->RCV_NXT, 
                            tcp_data->RCV_WND, false, si, entry);
                
                goto cleanup_on_error;
            }
            /* otherwise ACK is a duplicate; no need to do anything about it */

            /* Process segment text; put it into receive buffer (p74) */
            if (TCP_PAYLOAD_LEN(inc_packet) == 0) {
                /* Received packet contains no payload and is just ACK */
                send_return_packet = false;
            } 
            else {
                /* Process received packet, put into recv buffer */
                int bytes_written = 0;

                /* Write to buffer with blocking true */
                bytes_written = circular_buffer_write(&tcp_data->recv, 
                                (uint8_t *) TCP_PAYLOAD_START(inc_packet),
                                TCP_PAYLOAD_LEN(inc_packet), true);
                
                chilog(TRACE, "BYTES WRITTEN TO RECV: %d", 
                                bytes_written);
                
                /* Updating TCB and return header info */
                tcp_data->RCV_NXT += bytes_written;
                tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
                return_ack = 1;
                return_seq = chitcp_htonl(tcp_data->SND_NXT);
                return_ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                return_win = chitcp_htons(tcp_data->RCV_WND);
                send_return_packet = true;
                
                /* Find contiguous packets in OOD and process & free them */
                while (true) {
                    
                    /* Head is null -> no more packets in OOD */
                    if (!tcp_data->OOD) break;

                    rtq_packet_list_t *head = tcp_data->OOD;                    

                    /* Head of OOD is less than the packet we received; discard 
                     * the packet. This should only happen if we receive a pac
                     * from a previous incarnation of the program or if seq
                     * number overflows 
                     */
                    if (SEG_SEQ(head->packet) <= SEG_SEQ(inc_packet)) {
                        DL_DELETE(tcp_data->OOD, head);
                        free_rtq_packet(head);
                    } 

                    /* Process packet since it's contiguous */
                    else if (SEG_SEQ(head->packet) == 
                            SEG_SEQ(inc_packet) + TCP_PAYLOAD_LEN(inc_packet)) {
                        
                        /* Only process if space in buffer */
                        if (acceptable(head->packet, si, entry, false) == -1) {
                            return -1;
                            /* we do not want to break out of this loop
                               because of free at the end */
                        }

                        chitcp_tcp_packet_free(inc_packet);
                        
                        /* Set pointer to packet to parse & free from OOD */
                        inc_packet = head->packet;
                        DL_DELETE(tcp_data->OOD, head);
                        free(head);  
                        
                        bytes_written = circular_buffer_write(&tcp_data->recv, 
                                (uint8_t *) TCP_PAYLOAD_START(inc_packet),
                                TCP_PAYLOAD_LEN(inc_packet), true);
                
                        chilog(INFO, "Additional bytes from OOD received: %d", 
                                        TCP_PAYLOAD_LEN(inc_packet));
                        
                        /* Updating TCB and return header info */
                        tcp_data->RCV_NXT += bytes_written;
                        tcp_data->RCV_WND = circular_buffer_available(
                                                &tcp_data->recv);
                        return_ack = 1;
                        return_seq = chitcp_htonl(tcp_data->SND_NXT);
                        return_ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                        return_win = chitcp_htons(tcp_data->RCV_WND);
                    } 

                    /* SEQ(head) > SEQ(incoming) + LEN => non-contiguous */
                    else {  
                        break;
                    }
                }

                /* Logging */
                chilog(TRACE, "------------------");
                chilog(TRACE, "Bytes written: %i", bytes_written);
                chilog(TRACE, "------------------");

            }
        }

        /* Processing FIN/ACK based on RFC pages 75-76 */
        if (entry->tcp_state == ESTABLISHED || entry->tcp_state == CLOSE_WAIT) {
            /* Received <FIN> message */
            if (inc_header->fin) {
                /* Ack the FIN */
                send_return_packet = true;
                return_ack = 1;
                NEW_STATE = CLOSE_WAIT;
            }    
        } else if (entry->tcp_state == CLOSING) {
            /* FIN/ACK part */
            if (inc_header->fin && inc_header->ack) {
                
                /* stay in CLOSING */

            } else if (inc_header->ack) {
                if (tcp_data->SND_NXT == SEG_ACK(inc_packet)) {
                    /* if FIN ack'ed, move to TIME_WAIT */
                    send_return_packet = false;
                    
                    /* Updating to TIME_WAIT - not implemented */
                    NEW_STATE = TIME_WAIT;
                    if (NEW_STATE != entry->tcp_state) {
                        chitcpd_update_tcp_state(si, entry, NEW_STATE);
                    }

                    /* Immediately going to CLOSED, not implementing TIME_WAIT */
                    NEW_STATE = CLOSED; 
                } else {
                    /* Received ACK but not for our FIN, ignore segment */
                }
            }
        } else if (entry->tcp_state == FIN_WAIT_2) {
            /* FIN/ACK part */
            if (inc_header->fin && inc_header->ack) {
                /* if FIN received, ack their FIN + go to TIME_WAIT */
                send_return_packet = true;
                return_ack = 1;
                /* If this ack gets dropped, we have to resend. Means we have
                 * to delay closing */

                /* Updating to TIME_WAIT */
                NEW_STATE = TIME_WAIT;
                if (NEW_STATE != entry->tcp_state) {
                    chitcpd_update_tcp_state(si, entry, NEW_STATE);
                }
            } else if (inc_header->ack) {
                /* no FIN received, stay in FIN_WAIT_2 */
                send_return_packet = false;
            } else {
                return -1;
            }
        } else if (entry->tcp_state == FIN_WAIT_1) {
            /* FIN/ACK part */
            if (inc_header->fin && inc_header->ack) {
                if (tcp_data->SND_NXT == inc_header->ack) {
                    /* if FIN ack'ed + FIN received.
                       ack their FIN + go to TIME_WAIT */
                    send_return_packet = true;
                    return_ack = 1;
                    
                    /* Updating to TIME_WAIT */
                    NEW_STATE = TIME_WAIT;
                    if (NEW_STATE != entry->tcp_state) {
                        chitcpd_update_tcp_state(si, entry, NEW_STATE);
                    }

                    /* Immediately going to CLOSED, not implementing TIME_WAIT*/
                    NEW_STATE = CLOSED; 

                }
                else {
                    /* Received FIN, but our FIN not ack'ed yet. 
                       Ack their FIN + go to CLOSING */
                    send_return_packet = true;
                    return_ack = 1;
                    NEW_STATE = CLOSING;
                }

            } else if (inc_header->ack) {
                if (tcp_data->SND_NXT == SEG_ACK(inc_packet)) {
                    /* if FIN ack'ed, move to FIN_WAIT_2 */
                    send_return_packet = false;
                    NEW_STATE = FIN_WAIT_2;
                } else {
                    /* Received ACK but not for our FIN */
                    // send_return stays how it was according to processing
                    NEW_STATE = FIN_WAIT_1;
                }
            }
        } else if (entry->tcp_state == TIME_WAIT) {  
            /* Close connection when we get appropriate ACK with correct SEQ */
            /* This should be the only case where we need to resend the ACK */
            /* TODO: Make sure this is the only case where above is true */
            if (inc_header->ack) {
                NEW_STATE = CLOSED;
                if (NEW_STATE != entry->tcp_state) {
                    chitcpd_update_tcp_state(si, entry, NEW_STATE);
                }
            }
        }

    } else {
        chilog(ERROR, "unimplemented state in packet arrival received");
        return -1;
    }

    if (inc_packet) chitcp_tcp_packet_free(inc_packet);

    if (send_return_packet) {
        /* Create return packet, fill it with appropriate info, send it */
        tcp_packet_t *return_packet = calloc(1, sizeof(tcp_packet_t));
        int packetlen = chitcpd_tcp_packet_create(entry,
                                                return_packet, 
                                                payload, 
                                                payload_len);
        tcphdr_t *return_header = TCP_PACKET_HEADER(return_packet);

        return_header->syn = return_syn;
        return_header->ack = return_ack;       

        /* Following fields are in NETWORK byte order (big-endian) */
        return_header->seq = return_seq; 
        return_header->ack_seq = return_ack_seq;
        return_header->win = return_win;

        /* Logging */
        chilog(TRACE, "Sending return packet:");
        chilog_tcp(DEBUG, return_packet, LOG_OUTBOUND);

        /* Sending packet */
        send_packet(si, entry, return_packet, true);
    }

    /* Change state to appropriate state */
    chilog(TRACE, "Reached almost end of packet send.");
    if (NEW_STATE != entry->tcp_state) {
        chitcpd_update_tcp_state(si, entry, NEW_STATE);
    }
    
    return 0;

cleanup_on_error:
    if (inc_packet) chitcp_tcp_packet_free(inc_packet);
    return -1;
}

void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry) {
    
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
    if (USE_RANDOM_ISS) {
        srand(time(NULL));  // Sets the seed for random number generator
        tcp_data->ISS = (uint32_t) rand();
    } else {
        tcp_data->ISS = DEBUG_ISS;
    }

    /* Init RTO to 200 msecond until RTT measurement has been made per RFC */
    tcp_data->RTO = SECOND;

    /* Init SRTT and RTTVAR to 0 to indicate that they're not set */
    tcp_data->SRTT = 0;
    tcp_data->RTTVAR = 0;

    /* Multitimer init */
    uint16_t num_timers = 2;
    tcp_data->mt = (multi_timer_t*) calloc(1, sizeof(multi_timer_t));
    mt_init(tcp_data->mt, num_timers);
    
    /* Callback args */    
    callback_info_t *info = (callback_info_t *) calloc(1, 
                                                    sizeof(callback_info_t));
    info->si = si;
    info->entry = entry;
    
    /* OOD list. Kept in order of seq number */
    tcp_data->OOD = NULL;

    /* Retransmission queue. Kept in order */    
    tcp_data->RTQ = NULL;
    tcp_data->retransmission_callback = retransmission_callback;
    tcp_data->callback_args = info;

    /* Persist timer */
    tcp_data->persist_callback = persist_callback;
    tcp_data->probe_seg_active = false;
    tcp_data->probe_data = 0;


}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry) {
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    rtq_packet_list_destroy(&tcp_data->RTQ);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    mt_free(tcp_data->mt); 

    /* Cleanup of additional tcp_data_t fields goes here */
}


int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, 
                                    tcp_event_type_t event) {

    if (event == APPLICATION_CONNECT) {
        
        /* Create packet and get tcp data */
        tcp_packet_t *packet = (tcp_packet_t*) calloc(1, sizeof(tcp_packet_t));
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

        /* Initialize send buffer sequence num */
        circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->ISS + 1);

        /* Create packet with header and no payload */
        const uint8_t* payload = NULL;
        uint16_t payload_len = 0;
        int packetlen = chitcpd_tcp_packet_create(entry, packet, 
                                              payload, payload_len);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);

        /* Setting Transmission Control Block info */
        tcp_data->SND_UNA = tcp_data->ISS;
        tcp_data->SND_NXT = tcp_data->ISS+1;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);; 

        /* Construct header with SYN flag set */
        header->syn = 1;
        header->win = chitcp_htons(circular_buffer_available(&tcp_data->recv));
        header->seq = chitcp_htonl(tcp_data->ISS);
        
        /* Log header & payload */
        chilog(TRACE, "Sending SYN packet:");
        chilog_tcp(DEBUG, packet, LOG_OUTBOUND);

        /* Get time sent of packet */
        struct timespec *time_sent = calloc(1, sizeof(struct timespec));
        clock_gettime(CLOCK_REALTIME, time_sent);

        /* Sending packet */
        send_packet(si, entry, packet, true);

        
        /* Start retransmission timer for packet_sent */
        callback_info_t *info = (callback_info_t *) calloc(1, 
                                                    sizeof(callback_info_t));
        info->si = si;
        info->entry = entry;
        
        /* Change state from CLOSED to SYN-SENT */
        chitcpd_update_tcp_state(si, entry, SYN_SENT);
    }
    else if (event == CLEANUP) {
        /* Any additional cleanup goes here TODO */
    }
    else {
        chilog(WARNING, "In CLOSED state, received unexpected event.");
    }

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, 
                                        tcp_event_type_t event) {
    if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);
    }
    else {
        chilog(WARNING, "In LISTEN state, received unexpected event.");
    }

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, 
                                        tcp_event_type_t event) {   
    if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);
    }
    else if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    }
    else {
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");
    }

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, 
                                        tcp_event_type_t event) {
    if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);
    } else if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");
    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, 
                                            tcp_event_type_t event) {
    if (event == APPLICATION_SEND) {
        process_send_buffer(si, entry);
    } else if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);

        /* Check if we can initiate conn teardown */
        check_close(si, entry);
    } else if (event == APPLICATION_RECEIVE) {
        /* Socket layer already takes care of extracting data from receive buff 
           so we just have to update the receive window. It also handles
           the queueing of recv requests */
        
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);

        /* Receive window updated, publish it */
        send_ack(tcp_data->SND_NXT, tcp_data->RCV_NXT, tcp_data->RCV_WND, 
                        false, si, entry);
    } else if (event == APPLICATION_CLOSE) {
        /* Set closing flag and next state */
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->closing = true;
        tcp_data->NEXT_STATE = FIN_WAIT_1;

        /* Check if we can initiate conn teardown*/
        check_close(si, entry);

    } else if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else {
        chilog(WARNING, "In ESTABLISHED, unexpected event (%i).", event);
    }

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, 
                                            tcp_event_type_t event) {
    if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);
    } else if (event == APPLICATION_RECEIVE) {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else {
       chilog(WARNING, "In FIN_WAIT_1 state, unexpected event (%i).", event);
    }
    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, 
                                            tcp_event_type_t event) {
    if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);
    }
    else if (event == APPLICATION_RECEIVE) {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else {
        chilog(WARNING, 
                "In FIN_WAIT_2, received unexpected event (%i).", event);
    }

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, 
                                            tcp_event_type_t event) {
    if (event == APPLICATION_CLOSE) {

        /* Set closing & next state */
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->closing = true;
        tcp_data->NEXT_STATE = LAST_ACK;

        /* Check if we can initiate conn teardown */
        check_close(si, entry);

    } else if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);

        /* Check if we can initiate conn teardown */
        check_close(si, entry);
    }
    else if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    }
    else {
       chilog(WARNING, "In CLOSE_WAIT, received unexpected event (%i).", event);
    }

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, 
                                        tcp_event_type_t event) {
    if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);
    } else if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else {
       chilog(WARNING, "In CLOSING, received unexpected  event (%i).", event);
    }

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, 
                                        tcp_event_type_t event) {
    /* Only reaches here from FIN_WAIT_2, where our sent ack of the other 
     * person's fin might drop and we have to resend the ack. */
    if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);
    }
    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, 
                                        tcp_event_type_t event) {
    if (event == PACKET_ARRIVAL) {
        handle_packet_arrival(si, entry, event);
    } else if (event == TIMEOUT_RTX) {
        handle_timeout(si, entry);
    } else if (event == TIMEOUT_PST) {
        handle_persist_timeout(si, entry);
    } else {
       chilog(WARNING, "In LAST_ACK, received unexpected event (%i).", event);
    } 
    return CHITCP_OK;
}


/* See above declaration */
int rtq_packet_list_insert(rtq_packet_list_t **pl, tcp_packet_t *packet, 
                        struct timespec *time_sent)
{
    rtq_packet_list_t *elt = calloc(1, sizeof(rtq_packet_list_t));

    elt->packet = packet;

    if (time_sent != NULL) elt->time_sent = time_sent;

    DL_INSERT_INORDER(*pl, elt, compare_packets);

    return CHITCP_OK;
}


/* See chitcp_packet_list_size in packet.h */
int rtq_packet_list_size(rtq_packet_list_t *pl) {
    int count = 0;
    rtq_packet_list_t *elt;

    DL_COUNT(pl, elt, count);

    return count;
}


/* See chitcp_packet_list_destroy in packet.h */
int rtq_packet_list_destroy(rtq_packet_list_t **pl) {
    rtq_packet_list_t *elt, *tmp;

    DL_FOREACH_SAFE(*pl,elt,tmp) {
        DL_DELETE(*pl,elt);
        free_rtq_packet(elt);
    }

    return CHITCP_OK;
}


/* Frees a RTQ packet */
int free_rtq_packet(rtq_packet_list_t *pac) {
    chitcp_tcp_packet_free(pac->packet);

    if (pac->time_sent) free(pac->time_sent);

    free(pac);
    return 0;
}


/* Returns total bytes of data contained in packet */
uint32_t total_packet_content(tcp_packet_t *packet) {
    int has_synfin = TCP_PACKET_HEADER(packet)->fin || 
                    TCP_PACKET_HEADER(packet)->syn;
    return TCP_PAYLOAD_LEN(packet) + has_synfin;
}