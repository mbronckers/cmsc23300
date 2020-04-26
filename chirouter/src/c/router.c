/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When a router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
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
 *    software without specific prior written permission.
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
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

#include "chirouter.h"
#include "arp.h"
#include "utils.h"
#include "utlist.h"

/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * a router. This function receives the router context for the router that
 * received the frame, and the inbound frame (the ethernet_frame_t struct
 * contains a pointer to the interface where the frame was received).
 * Take into account that the chirouter code will free the frame after this
 * function returns so, if you need to persist a frame (e.g., because you're
 * adding it to a list of withheld frames in the pending ARP request list)
 * you must make a deep copy of the frame.
 *
 * chirouter can manage multiple routers at once, but does so in a single
 * thread. i.e., it is guaranteed that this function is always called
 * sequentially, and that there will not be concurrent calls to this
 * function. If two routers receive Ethernet frames "at the same time",
 * they will be ordered arbitrarily and processed sequentially, not
 * concurrently (and with each call receiving a different router context)
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 *   Note: In the event of a critical error, the entire router will shut down and exit.
 *         You should only return -1 for issues that would prevent the router from
 *         continuing to run normally. Return 1 to indicate that the frame could
 *         not be processed, but that subsequent frames can continue to be processed.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /* Access header info  */
    ethhdr_t *header = (ethhdr_t *) frame->raw;
    uint16_t ethertype = ntohs(header->type);
    
    char *ethertype_str;
    switch(ethertype) {
        case ETHERTYPE_IP:
            ethertype_str = "IPv4";
            process_ipv4(ctx, frame);
            break;
        case ETHERTYPE_ARP:
            process_arp(ctx, frame);
            break;
        case ETHERTYPE_IPV6:
            break;
        default:
            ethertype_str = "Other";
    }
    
    chilog(TRACE, "Received frame of type: %s", ethertype_str);

    return 0;
}

/*
 * Processes IPv4 datagrams
 *
 * Currently only handles IPv4 datagrams directed to one of the router's IPs
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 */
int process_ipv4(chirouter_ctx_t *ctx, ethernet_frame_t *frame) {
    /* Accessing an headers */
    ethhdr_t* inc_eth = (ethhdr_t*) (frame->raw);
    iphdr_t* inc_ip = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    icmp_packet_t* inc_icmp;

    /* Final destination is one of our interfaces; means no forwarding */
    bool dst_is_router = false;
    bool contains_icmp = false;
    chirouter_interface_t* inc_iface = NULL;   // interface on which datagram arrived

    /* Check if IP is meant for one of router's iface IPs. Discard the frame
     * if it is not meant for any of the interfaces */
    for (int i = 0; i < ctx->num_interfaces; i++) {
        chirouter_interface_t* iface = &(ctx->interfaces[i]);

        /* IP datagram DST is one of our interfaces */
        if (ethernet_addr_is_equal(inc_eth->dst, iface->mac)) {
            inc_iface = iface;
        }
        
        if (inc_ip->dst == iface->ip.s_addr) {
            dst_is_router = true;
        }
    }

    /* Incoming packet doesn't match interface. Drop the packet. */
    if (!inc_iface) {
        chilog(ERROR, "Received packet that does not match any interface's MAC");
        return 1;
    }

    /* IP datagram contains ICMP message */
    if (inc_ip->proto == ICMP_PROTO) {
        contains_icmp = true;
        inc_icmp = (icmp_packet_t*) (frame->raw + sizeof(ethhdr_t)+ sizeof(iphdr_t));
    }

    /* IP datagram is a TCP/UDP segment directed towards one of the interfaces */
    bool tdp_udp = (inc_ip->proto == TCP_PROTO || inc_ip->proto == UDP_PROTO)
                   && dst_is_router;

    /* We for now send a destination unreachable replies if appropriate */
    bool host_unreachable = dst_is_router
                            && inc_iface->ip.s_addr != inc_ip->dst;

    /* If DST is not router, check routing table for <IP/MAC> of datagram */
    bool found_subnet_match = dst_is_router;

    /* Gateway we need MAC address of, used for ARP request if not 0.0.0.0 */
    in_addr_t gateway = 0;  // network order

    chirouter_interface_t *out_iface = NULL;
    if (!found_subnet_match) {
        
        /* Iterate over routing table. Find longest prefix match */
        in_addr_t largest_mask_val = 0;

        for (int i = 0; i < ctx->num_rtable_entries; i++) {
            chirouter_rtable_entry_t *entry = &ctx->routing_table[i];

            /* Everything here is network-byte order so no need to flip */
            /* note: order of operations is important -- keep parentheses */

            /* Longest prefix match: larger mask (host order) means longer prefix */
            
            if ((entry->mask.s_addr & entry->dest.s_addr) == 
                (entry->mask.s_addr & inc_ip->dst)) {

                found_subnet_match = true;
                in_addr_t mask_val = ntohs(entry->mask.s_addr);
                
                /* Greater or equal is to account for default gateway */
                if (mask_val >= largest_mask_val) {
                    largest_mask_val = mask_val;
                    out_iface = entry->interface;      // to use to fwd datagram / send ARP
                    gateway = entry->gw.s_addr;
                }

            }
        }
    } 

    bool found_arp_match = false;
    chirouter_arpcache_entry_t* arp_entry;
    

    /* Check for and send appropriate icmp dest unreachable response */
    if (!found_subnet_match || tdp_udp || host_unreachable) {
        uint8_t icmp_code = 0;
        
        /* Port Unreachable */
        if (tdp_udp) {
            icmp_code = ICMPCODE_DEST_PORT_UNREACHABLE;
        } else if (!found_subnet_match) {
            icmp_code = ICMPCODE_DEST_NET_UNREACHABLE;
        } else if (host_unreachable) {
            icmp_code = ICMPCODE_DEST_HOST_UNREACHABLE;
        } 
        
        send_icmp(ctx, inc_eth, inc_ip, inc_iface, 
                                ICMPTYPE_DEST_UNREACHABLE, icmp_code);
        
        return 0;
    }

    /* ICMP Echo Request for one of interfaces' IPs, time not exceeded */ 
    else if (dst_is_router && contains_icmp && 
        inc_icmp->type == ICMPTYPE_ECHO_REQUEST) {
        
        /* Construct ICMP Echo Reply (Type 0) */

        /* Length of ICMP Echo is equal to the of length inc_ip - ICMP hdr size */
        uint16_t reply_icmp_payload_len = ntohs(inc_ip->len) - sizeof(iphdr_t) - ICMP_HDR_SIZE;
        int reply_len = sizeof(ethhdr_t) + sizeof(iphdr_t) +
                         ICMP_PACKET_ECHO_SIZE(reply_icmp_payload_len);
        chilog(DEBUG, "Incoming IP len: <%i>", ntohs(inc_ip->len));
        chilog(DEBUG, "Reply payload len: <%u>", reply_icmp_payload_len);

        uint8_t reply[reply_len];
        memset(reply, 0, reply_len);

        /* Set ethernet header info */
        ethhdr_t* reply_eth = (ethhdr_t*) reply;
        memcpy(&reply_eth->dst, &inc_eth->src, ETHER_ADDR_LEN);
        memcpy(&reply_eth->src, &inc_iface->mac, ETHER_ADDR_LEN);
        reply_eth->type = htons(ETHERTYPE_IP);

        /* Set IP header info (addr are in network order already) */
        iphdr_t* reply_ip = (iphdr_t*) (reply + sizeof(ethhdr_t));
        reply_ip->ihl = DEFAULT_IHL;
        reply_ip->version = DEFAULT_VERSION;

        reply_ip->tos = 0;
        reply_ip->len = htons(reply_len - sizeof(ethhdr_t));
        reply_ip->id = htons(0);       // should create a rand() as ID?
        reply_ip->off = htons(0);      // double check
        reply_ip->ttl = 64;            // recommended initial value
        reply_ip->proto = ICMP_PROTO;
        
        memcpy(&reply_ip->src, &inc_iface->ip.s_addr, IPV4_ADDR_LEN);
        memcpy(&reply_ip->dst, &inc_ip->src, IPV4_ADDR_LEN);

        /* checksum always needs to be last in header info setting */
        reply_ip->cksum = cksum(reply_ip, sizeof(iphdr_t));

        /* Set ICMP packet info */
        icmp_packet_t* reply_icmp = (icmp_packet_t*) (reply + 
                                                      sizeof(ethhdr_t) +
                                                      sizeof(iphdr_t));
        reply_icmp->type = 0;
        reply_icmp->code = ICMPTYPE_ECHO_REPLY;

        reply_icmp->echo.identifier = inc_icmp->echo.identifier;
        reply_icmp->echo.seq_num = inc_icmp->echo.seq_num;
        
        /* Copy data payload */
        memcpy(&reply_icmp->echo.payload, &inc_icmp->echo.payload, reply_icmp_payload_len);

        /* important: proper checksum or else packet is dropped by mininet */
        reply_icmp->chksum = cksum(reply_icmp, ntohs(inc_ip->len) - sizeof(iphdr_t));

        /* Logging */
        chilog(TRACE, "Echo Reply information...");
        chilog_ethernet(TRACE, reply, reply_len, LOG_OUTBOUND);
        chilog_ip(TRACE, reply_ip, LOG_OUTBOUND);
        chilog_icmp(TRACE, reply_icmp, LOG_OUTBOUND);
        chilog(TRACE, "Echo Reply information END...");

        /* Send reply to sender from interface the datagram came in on */
        chirouter_send_frame(ctx, inc_iface, reply, reply_len);
        return 0;
    }

    /* Forward IP datagram if there is a subnet match & router is not DST */
    if (!dst_is_router && found_subnet_match) {
        
        /* Check ARP cache for incoming datagram IP destination */
        struct in_addr *forward_ip = (struct in_addr*) calloc(1, sizeof(struct in_addr));

        /* If gateway is 0.0.0.0, we should know the 
         * address of the receiving node, so we look that up. Otherwise,
         * we route the packet to the gateway IP address for it to deal with
         */
        if (gateway == 0) {
            forward_ip->s_addr = inc_ip->dst;
        } else {
            forward_ip->s_addr = gateway;
        }
        
        pthread_mutex_lock(&ctx->lock_arp);
        arp_entry = chirouter_arp_cache_lookup(ctx, forward_ip);
        pthread_mutex_unlock(&ctx->lock_arp);
        
        /* Send ARP request if we don't know the address translation */
        if (arp_entry == NULL) {

            /* Create broadcast MAC & any IP addr (network order, fyi)
             * since we want the receiving network to broadcast the ARP request
             * to all the devices on that network */
            uint8_t eth_dst_broadcast[ETHER_ADDR_LEN];
            uint8_t target_mac[ETHER_ADDR_LEN];

            for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                eth_dst_broadcast[i] = 0xFF;
                target_mac[i] = 0x00;
            }

            /* Send ARP request and it to pending */
            pthread_mutex_lock(&ctx->lock_arp);

            /* Check if we already have a pending ARP request for this IP */
            chirouter_pending_arp_req_t *pend_arp = 
                chirouter_arp_pending_req_lookup(ctx, forward_ip);
            
            /* None found: create ARP Request, add to pending queue & send it */
            if (!pend_arp) {
                pend_arp = chirouter_arp_pending_req_add(ctx, forward_ip, out_iface);
                send_arp(ctx, eth_dst_broadcast, out_iface, ARP_OP_REQUEST, 
                      target_mac, forward_ip->s_addr);
            }
            
            /* Add to-be-sent frame to withheld frames under pending ARP req */
            chirouter_arp_pending_req_add_frame(ctx, pend_arp, frame);

            pthread_mutex_unlock(&ctx->lock_arp);

            return 0;

        } 

        /* Found MAC/IP translation in ARP cache and need to forward the packet */
        else {
            /* Set host unreachable to false since we now know the MAC addr */
            found_arp_match = true;
            host_unreachable = false;
        }
    }

    /* Found ARP match, so now forward IP datagram on out_iface */
    if (found_arp_match && out_iface != NULL) {
        
        /* If TTL = 1, respond ICMP Time Exceeded */
        if (inc_ip->ttl == 1) {

            send_icmp(ctx, inc_eth, inc_ip, inc_iface, 
                        ICMPTYPE_TIME_EXCEEDED, 0);

            return 0;
        }

        /* Allowed to reuse existing headers in IP fwding */
        memcpy(inc_eth->src, out_iface->mac, ETHER_ADDR_LEN);
        memcpy(inc_eth->dst, arp_entry->mac, ETHER_ADDR_LEN);
        inc_ip->ttl -= 1;

        /* Recompute checksum with the new ttl in existing header */
        inc_ip->cksum = 0;
        inc_ip->cksum = cksum(inc_ip, sizeof(iphdr_t));
        chirouter_send_frame(ctx, out_iface, frame->raw, frame->length);

        chilog(INFO, "Forwarded IP datagram");
    } else if (found_arp_match && !found_subnet_match) {
        chilog(WARNING, "Found ARP match but no subnet match");
    }
    
    return 0;

}

/*
 * Processes arp messages 
 *
 * TODO: Currently only handles ARP REQUESTS for the interface it receives it on
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 */
int process_arp(chirouter_ctx_t *ctx, ethernet_frame_t *frame) {
    
    /* Accessing an ARP message */
    ethhdr_t* inc_eth = (ethhdr_t*) (frame->raw);
    arp_packet_t* inc_arp = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));
    
    /* Handle ARP requests */
    if (ntohs(inc_arp->op) == ARP_OP_REQUEST) {
        /* Create & set IP address */
        uint32_t tpa = inc_arp->tpa;    // target IP of received ARP (network order)

        /* Logging */
        chilog(TRACE, "ARP request for IP: ");
        log_IP(TRACE, tpa);

        /* Check if ARP request is for an interface IP address */
        for (int i = 0; i < ctx->num_interfaces; i++) {
            chirouter_interface_t* iface = &(ctx->interfaces[i]);
            
            /* note: ip addrs in ctx are stored in network order */
            if (tpa == iface->ip.s_addr) {
                chilog(TRACE, "Incoming ARP request is for one of our interfaces");

                send_arp(ctx, inc_eth->src, iface, ARP_OP_REPLY, inc_arp->sha, inc_arp->spa);

                return 0;
            }
        }    
        
        chilog(WARNING, "Received ARP request not meant for router <%s>", ctx->name);
        chilog_arp(WARNING, inc_arp, LOG_INBOUND);
        
        return -1;
  
    }
    
    /* If we receive ARP reply, do:
     * 1. add IP/MAC mapping to ARP cache
     * 2. fetch pending req from list & forward all withheld frames
     * 3. free ARP req from pending ARP req list 
     */
    else if (ntohs(inc_arp->op) == ARP_OP_REPLY) {
        
        /* Find source IP address */
        struct in_addr* source_ip = (struct in_addr*) calloc(1, sizeof(struct in_addr));
        source_ip->s_addr = inc_arp->spa;

        /* Find source MAC address of incoming ARP reply */
        uint8_t source_mac[ETHER_ADDR_LEN];
        memcpy(&source_mac, &inc_arp->sha, ETHER_ADDR_LEN);

        /* Add entry to cache */
        pthread_mutex_lock(&(ctx->lock_arp));
        chirouter_arp_cache_add(ctx, source_ip, source_mac);
        pthread_mutex_unlock(&(ctx->lock_arp));
        
        chilog(DEBUG, "Added ARP mapping to cache.");

        /* Check for pending request and forward withheld frames */
        pthread_mutex_lock(&(ctx->lock_arp));
        chirouter_pending_arp_req_t* pending_req = 
            chirouter_arp_pending_req_lookup(ctx, source_ip);

        if (!pending_req) {
            pthread_mutex_unlock(&(ctx->lock_arp));
            return 0;
        }

        /* There is a pending ARP Req for this ip; forward all withheld frames */
        withheld_frame_t *withheld_frame;
        DL_FOREACH(pending_req->withheld_frames, withheld_frame) {
            ethhdr_t* inc_eth = (ethhdr_t*) (withheld_frame->frame->raw);
            iphdr_t* inc_ip = (iphdr_t*) (withheld_frame->frame->raw +
                                             sizeof(ethhdr_t));

            /* Find the inbound interface to send the reply to */
            uint8_t inbound_mac[ETHER_ADDR_LEN];
            chirouter_interface_t *inbound_iface = NULL;
            
            for (int i = 0; i < ctx->num_interfaces; i++) {
                chirouter_interface_t *iface = &(ctx->interfaces[i]);
                if (ethernet_addr_is_equal(inc_eth->dst, iface->mac)) {
                    inbound_iface = iface;
                    break;
                }
            }

            /* Reply ICMP Time Exceeded */
            if (inc_ip->ttl == 1) {

                send_icmp(ctx, inc_eth, inc_ip, inbound_iface, 
                                ICMPTYPE_TIME_EXCEEDED, 0);
            } 

            /* Forward IP datagram */
            else {
                
                /* Allowed to reuse existing headers in IP fwding */
                memcpy(inc_eth->src, pending_req->out_interface->mac, ETHER_ADDR_LEN);
                memcpy(inc_eth->dst, source_mac, ETHER_ADDR_LEN);
                inc_ip->ttl -= 1;
                
                /* Recompute checksum with the new ttl */
                inc_ip->cksum = 0;
                inc_ip->cksum = cksum(inc_ip, sizeof(iphdr_t));

                chirouter_send_frame(ctx, pending_req->out_interface, 
                                        withheld_frame->frame->raw, 
                                        withheld_frame->frame->length);

                chilog(INFO, "Forwarded IP datagram delayed - on ARP REPLY");
            }
        }

        /* Remove this arp req from the arp list. TODO: memory management??? */
        DL_DELETE(ctx->pending_arp_reqs, pending_req);
        free(pending_req);  // Don't free underlying parts; they're pointers
        pthread_mutex_unlock(&(ctx->lock_arp));
    }   

    return 0;
}

/* 
 * Sends ARP packets from @param out_iface to @param dst 
 * 
 * @param eth_dst_mac - target hardware address (Ethernet hdr)
 * @param out_iface - interface to send ARP packet from
 * @param arp_op - should be in HOST ORDER; we convert in the function
 * @param tha - target hardware address (ARP packet)
 * @param tpa - target protocol address (ARP packet)
 *
 * Returns: nothing
 */
void send_arp(chirouter_ctx_t* ctx, uint8_t* eth_dst_mac, 
                chirouter_interface_t* out_iface, uint16_t arp_op,
                uint8_t* tha, uint32_t tpa) 
{
    /* Construct reply */
    int reply_len = sizeof(ethhdr_t) + sizeof(arp_packet_t);
    uint8_t reply[reply_len];
    memset(reply, 0, reply_len);

    /* Set ethernet header info */
    ethhdr_t* reply_eth = (ethhdr_t*) reply;
    memcpy(&reply_eth->dst, eth_dst_mac, ETHER_ADDR_LEN);
    memcpy(&reply_eth->src, out_iface->mac, ETHER_ADDR_LEN);
    reply_eth->type = htons(ETHERTYPE_ARP);

    /* Set arp packet info */
    arp_packet_t* reply_arp = (arp_packet_t*) (reply + sizeof(ethhdr_t));
    reply_arp->hrd = htons(ARP_HRD_ETHERNET);
    reply_arp->pro = htons(ETHERTYPE_IP);
    reply_arp->hln = ETHER_ADDR_LEN;
    reply_arp->pln = IPV4_ADDR_LEN;
    reply_arp->op = htons(arp_op);
    
    /* Already in network order */
    memcpy(&reply_arp->sha, &out_iface->mac, ETHER_ADDR_LEN);
    memcpy(&reply_arp->spa, &out_iface->ip.s_addr, IPV4_ADDR_LEN);
    memcpy(&reply_arp->tha, tha, ETHER_ADDR_LEN);
    memcpy(&reply_arp->tpa, &tpa, IPV4_ADDR_LEN);

    /* Logging */
    chilog_ethernet(TRACE, reply, reply_len, LOG_OUTBOUND);
    chilog_arp(TRACE, reply_arp, LOG_OUTBOUND);

    /* Send reply to sender from interface the ARP req came in on */
    chirouter_send_frame(ctx, out_iface, reply, reply_len);
}

/* 
 * Logs 32 unsigned ints to IP (x.x.x.x) format
 * source: https://stackoverflow.com/questions/1680365/integer-to-ip-address-c
 */
int log_IP(loglevel_t LEVEL, uint32_t ip) 
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    chilog(LEVEL, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

    return 0;
}

/* See declaration in chirouter.h */
int send_icmp(chirouter_ctx_t *ctx, ethhdr_t* inc_eth, 
    iphdr_t* inc_ip, chirouter_interface_t* iface, uint8_t icmp_type, uint8_t icmp_code)
{
    int icmp_packet_size;
    if (icmp_type == ICMPTYPE_DEST_UNREACHABLE) {
        icmp_packet_size = ICMP_PACKET_UNREACHABLE_SIZE;
    } else if (icmp_type == ICMPTYPE_TIME_EXCEEDED) {
        icmp_packet_size = ICMP_PACKET_TIME_SIZE;
    }
    
    int reply_len = sizeof(ethhdr_t) + sizeof(iphdr_t) + icmp_packet_size;
    uint8_t reply[reply_len];
    memset(reply, 0, reply_len);

    /* Set ethernet header info. TODO: refactor */
    ethhdr_t* reply_eth = (ethhdr_t*) reply;
    memcpy(&reply_eth->dst, &inc_eth->src, ETHER_ADDR_LEN);
    memcpy(&reply_eth->src, &iface->mac, ETHER_ADDR_LEN);
    reply_eth->type = htons(ETHERTYPE_IP);

    /* Set IP header info (addr are in network order already) */
    iphdr_t* reply_ip = (iphdr_t*) (reply + sizeof(ethhdr_t));
    reply_ip->ihl = DEFAULT_IHL;
    reply_ip->version = DEFAULT_VERSION;

    reply_ip->tos = 0;
    reply_ip->len = htons(reply_len - sizeof(ethhdr_t));
    reply_ip->id = htons(0);
    reply_ip->off = htons(0);
    reply_ip->ttl = 64;
    reply_ip->proto = ICMP_PROTO;
    memcpy(&reply_ip->src, &inc_ip->dst, IPV4_ADDR_LEN);
    memcpy(&reply_ip->dst, &inc_ip->src, IPV4_ADDR_LEN);

    /* Checksum is equal to the ones complement sum of all words
        * in the header, where the checksum field is 0 before computing it */
    reply_ip->cksum = cksum(reply_ip, sizeof(iphdr_t));

    /* Set ICMP packet info */
    icmp_packet_t* reply_icmp = (icmp_packet_t*) (reply + 
                                                    sizeof(ethhdr_t) +
                                                    sizeof(iphdr_t));

    reply_icmp->type = icmp_type;
    reply_icmp->code = icmp_code;

    /* Fill in internet header into icmp payload + first 8 bytes of data */
    memcpy(&reply_icmp->dest_unreachable.payload, 
            inc_ip, sizeof(iphdr_t) + 8);

    /* IMPORTANT: proper checksum or else packet is dropped by mininet */
    reply_icmp->chksum = cksum(reply_icmp, ICMP_PACKET_UNREACHABLE_SIZE);

    /* Send reply to sender from interface the datagram came in on */
    chirouter_send_frame(ctx, iface, reply, reply_len);
    return 0;
}