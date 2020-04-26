/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  An API for managing multiple timers
 */

/*
 *  Copyright (c) 2013-2019, The University of Chicago
 *  Copyright (c) 2013-2019, The University of Chicago
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "chitcp/multitimer.h"
#include "chitcp/log.h"


/* Comparator function for LL_INSERT_INORDER
 * Compares two timers. Inactive timers have time = infinity effectively.
 * When comparing two inactive timers, returns equality (if only we could
 * treat infinites in math as all equal :'( 
 * 
 * Acive goes before inactive. Earlier expiry goes before later.
 *
 * Returns:
 *     -1 : timer1 goes before timer2
 *      0 : timer1 equals timer2; let LL_INSERT_INORDER do its thing
 *      1 : timer1 goes after timer2
 */
int compare_timers(single_timer_t* t1, single_timer_t* t2);

/* See declaration above */
int compare_timers(single_timer_t* t1, single_timer_t* t2) {
    
    if (t1->active && t2->active) {
        struct timespec temp;
        timespec_subtract(&temp, &(t1->expiry_time), &(t2->expiry_time));

        if (temp.tv_sec < 0) return -1;
        
        if (temp.tv_sec == 0) {
          
            /* Seconds for both timers are equal, so check nanoseconds */
            if (temp.tv_nsec < 0) return -1;
            if (temp.tv_nsec == 0) return 0;
            else return 1;

        }

        if (temp.tv_sec > 0) return 1;
    }
    
    /* Either t1, t2, or both are inactive. Active one goes before inactive */
    if (t1->active) return -1;
    if (t2->active) return 1;

    return 0;
}


/* See multitimer.h */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y) {
    struct timespec tmp;
    tmp.tv_sec = y->tv_sec;
    tmp.tv_nsec = y->tv_nsec;

    /* Perform the carry for the later subtraction by updating tmp. */
    if (x->tv_nsec < tmp.tv_nsec) {
        uint64_t sec = (tmp.tv_nsec - x->tv_nsec) / SECOND + 1;
        tmp.tv_nsec -= SECOND * sec;
        tmp.tv_sec += sec;
    }
    if (x->tv_nsec - tmp.tv_nsec > SECOND) {
        uint64_t sec = (x->tv_nsec - tmp.tv_nsec) / SECOND;
        tmp.tv_nsec += SECOND * sec;
        tmp.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - tmp.tv_sec;
    result->tv_nsec = x->tv_nsec - tmp.tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < tmp.tv_sec || 
            x->tv_sec == tmp.tv_sec && result->tv_nsec < 0;
}


/* See multitimer.h */
int mt_init(multi_timer_t *mt, uint16_t num_timers) {

    struct timespec now;
    clockid_t clk_id = CLOCK_REALTIME;
    clock_gettime(clk_id, &now);

    /* Head of LL needs to be init to NULL for utlist */
    if (num_timers == 0) mt->timers = NULL;
    mt->kill_timer_thread = 0;

    pthread_mutex_init(&mt->cv_lock, NULL);
    pthread_cond_init(&mt->cv, NULL);
    pthread_mutex_init(&mt->tt_lock, NULL);
    pthread_cond_init(&mt->tt_cv, NULL);
    
    for (int i = 0; i < num_timers; i++) {
        single_timer_t* new_timer;
        new_timer = (single_timer_t*) calloc(1, sizeof(single_timer_t));
        
        if (new_timer == NULL) return CHITCP_ENOMEM;
        
        /* Set new_timer properties */
        new_timer->active = false;
        new_timer->id = i;
        new_timer->next = NULL;
        new_timer->num_timeouts = 0;
        
        /* Set the expiry time to now as a placeholder */
        memcpy(&new_timer->expiry_time, &now, sizeof(struct timespec));

        /* Append new timer to list of timers in multitimer */
        LL_APPEND(mt->timers, new_timer);
    }
    
    /* TRACE logging */
    mt_chilog(TRACE, mt, false);

    /* Initialize timer thread */
    pthread_t worker_thread;   
    
    /* See multi_timer_t struct on tt_lock usage & purpose */
    pthread_mutex_lock(&mt->tt_lock);
    
    chilog(TRACE, "Thread creation starting...");
    
    /* Create timer thread */
    if (pthread_create(&worker_thread, NULL, start_mt_thread, mt) != 0) {
        chilog(ERROR, "Could not create the timer thread");
        return CHITCP_ETHREAD;
    } 

    /* Locking to ensure timer_thread gets to waiting state */
    pthread_cond_wait(&mt->tt_cv, &mt->tt_lock);
    pthread_mutex_unlock(&mt->tt_lock);
    
    /* This thread should block until timer thread starts sleeping 
     * the following lock ensures that */
    pthread_mutex_lock(&mt->cv_lock);
    pthread_mutex_unlock(&mt->cv_lock);

    chilog(TRACE, "Thread creation done.");

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_free(multi_timer_t *mt) {

    chilog(TRACE, "mt_free called");

    mt->kill_timer_thread = 1;
    
    /* Main thread cannot wake up timer_thread until tt reaches timedwait */
    pthread_mutex_lock(&mt->tt_lock);
    pthread_mutex_lock(&mt->cv_lock);
    
    chilog(TRACE, "Timer condvar signaled from mt_free");
    
    pthread_cond_signal(&mt->cv); // Freeing of memory happens in timer thread
    pthread_mutex_unlock(&mt->cv_lock);

    /* Wait until everything is freed before we terminate from this function
       Otherwise the stack memory gets screwed up because this function
       terminates and this causes issues in the still running timer thread */

    pthread_cond_wait(&mt->tt_cv, &mt->tt_lock);
    pthread_mutex_unlock(&mt->tt_lock);
    
    return CHITCP_OK;
}


/* See multitimer.h */
int mt_get_timer_by_id(multi_timer_t *mt, uint16_t id, single_timer_t **timer) {

    if (mt && mt->timers) {
        single_timer_t* temp;
        LL_FOREACH(mt->timers, temp) {
            if (temp->id == id) {
                *timer = temp;
                return CHITCP_OK;
            }
        }
    }

    return CHITCP_EINVAL;
}


/* See multitimer.h */
int mt_set_timer(multi_timer_t *mt, uint16_t id, uint64_t timeout, 
                    mt_callback_func callback, void* callback_args) {   
    
    single_timer_t* temp;
    if (mt_get_timer_by_id(mt, id, &temp) == CHITCP_EINVAL) {
        chilog(WARNING, "Could not find timer by id <%i>", id);
        return CHITCP_EINVAL;
    }
    
    /* Timer already active; cannot set */
    if (temp -> active) {
        chilog(WARNING, "Tried to set already active timer <%i>", id);
        return CHITCP_EINVAL;
    }

    /* Current clock time */
    clock_gettime(CLOCK_REALTIME, &(temp->expiry_time));

    /* Set expiry_time to now + timeout */
    temp->expiry_time.tv_sec  += timeout / SECOND;
    temp->expiry_time.tv_nsec += timeout % SECOND;
    
    /* Account for nanosecond overflow; carry over to seconds */
    if (temp->expiry_time.tv_nsec > SECOND) {
        temp->expiry_time.tv_nsec -= SECOND;
        temp->expiry_time.tv_sec += 1;
    }
    temp->callback = callback;
    temp->callback_args = callback_args;
    temp->active = true;

    pthread_mutex_lock(&mt->cv_lock);
    
    /* Set timer such that the first in LL is the earliest to expire
       i.e. update/insert_in_order */

    LL_DELETE(mt->timers, temp);
    LL_INSERT_INORDER(mt->timers, temp, compare_timers);
    
    /* Logging */
    chilog(WARNING, "Set timer <%d> for <%ld> microseconds", temp->id, timeout/1000);
    mt_chilog_single_timer(TRACE, temp);

    /* Wake up timer thread to update wait time if necessary; only necessary
     * if the timer we just set is set to expire sooner than all else */
    if (mt->timers == temp) {
        chilog(TRACE, "Timer condvar signaled from mt_set_timer");
        pthread_cond_signal(&mt->cv);
    }

    pthread_mutex_unlock(&mt->cv_lock);


    return CHITCP_OK;
}


/* See multitimer.h */
int mt_cancel_timer(multi_timer_t *mt, uint16_t id)
{
    single_timer_t* temp;
    
    if (mt_get_timer_by_id(mt, id, &temp) == CHITCP_EINVAL) {
        chilog(WARNING, "Could not find timer by id <%i>", id);
        return CHITCP_EINVAL;
    }
    
    if (!temp->active) {
        chilog(WARNING, "Tried canceling inactive timer <%i>", id);
        return CHITCP_EINVAL;
    }
    
    char* name = strdup(temp->name);
    
    pthread_mutex_lock(&mt->cv_lock);
    bool update_wait_time;
    temp->active = false;

    LL_DELETE(mt->timers, temp);
    LL_INSERT_INORDER(mt->timers, temp, compare_timers);
    
    chilog(DEBUG, "Canceled %s timer <%d>", name, id);

    /* Need to wake up timer thread and update wait time if we removed the
       head of the list, which is first timer to expire */
    update_wait_time = (mt->timers == temp);
    if (update_wait_time) {
        chilog(TRACE, "Timer condvar signaled from mt_cancel_timer");
        pthread_cond_signal(&mt->cv);
    }

    pthread_mutex_unlock(&mt->cv_lock);
    
    free(name);
    
    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer_name(multi_timer_t *mt, uint16_t id, const char *name)
{
    single_timer_t* timer;
    if (mt_get_timer_by_id(mt, id, &timer) == CHITCP_OK) {
        
        if (!timer->active) {
            chilog(WARNING, "Cannot set inactive timer <%d>'s name", id);
            return CHITCP_EINVAL;
        }
        
        strncpy(timer->name, name, MAX_TIMER_NAME_LEN + 1);
        
        return CHITCP_OK;
    }

    return CHITCP_EINVAL;
}


/* See multitimer.h */
int mt_chilog_single_timer(loglevel_t level, single_timer_t *timer) {
    struct timespec now, diff;

    /* Clock time */
    clockid_t clk_id = CLOCK_REALTIME;
    
    if (timer->active) {
        
        /* Get wall time */        
        clock_gettime(clk_id, &now);
        
        /* Compute difference between timer expiry and current time */
        if (timespec_subtract(&diff, &(timer->expiry_time), &now) == 1) {
            chilog(TRACE, "Difference negative - timer <%i> expired", timer->id);
        }

        chilog(level, "Active ID <%i> name: <%s> | %lis %lins", 
                 timer->id, timer->name, diff.tv_sec, diff.tv_nsec);
    } else {
        chilog(level, "Inactive ID <%i> name: <%s>", timer->id, timer->name);
    }

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_chilog(loglevel_t level, multi_timer_t *mt, bool active_only) {
    single_timer_t* temp;

    chilog(level, "--------- start of multitimer log ---------");
    LL_FOREACH(mt->timers, temp) {
        if (!active_only || temp->active) {
            mt_chilog_single_timer(level, temp);
        }
    }
    chilog(level, "--------- end of multitimer log ---------");

    return CHITCP_OK;
}

/* See multitimer.h */
void* start_mt_thread(void *args) {
    multi_timer_t *mt = (multi_timer_t *) args;

    /* Spurious wakes will just update timer information and won't affect
     * anything if timers are not set to go off; we shouldn't need to worry */
    bool any_timer_active = false;
    
    /* Get wait_until_time for timer_thread to wait until */
    struct timespec wait_until_time;
    clock_gettime(CLOCK_REALTIME, &(wait_until_time));

    pthread_mutex_lock(&mt->cv_lock);
    
    /* Main thread will wake up from this condvar signal, but it cannot
     * proceed until this thread enter the pthread_cond_wait because cv_lock
     * is locked until pthread_cond_wait is called which unlocks it */
    pthread_mutex_lock(&mt->tt_lock);
    pthread_cond_signal(&mt->tt_cv);  
    pthread_mutex_unlock(&mt->tt_lock);
    
    while (true) {
        
        if (any_timer_active) {
            
            /* Update the wait time of thread */            
            chilog(TRACE, "Timed Waiting State...");
            chilog(TRACE, "Wait until time <%lld> s <%lld> ns", 
                    wait_until_time.tv_sec, wait_until_time.tv_nsec);
            
            pthread_cond_timedwait(&mt->cv, &mt->cv_lock, &wait_until_time);
        
        } else {  
            /* Wait until a timer set/unlock event is triggered,
               since no timer is set */
            chilog(TRACE, "Infinite Waiting State...");
            pthread_cond_wait(&mt->cv, &mt->cv_lock); 
            chilog(TRACE, "Done with infinite waiting...");  
        }

        if (mt->kill_timer_thread) {
            if (mt && mt->timers) {
                single_timer_t* timer = mt->timers;
                single_timer_t* temp;
                LL_FOREACH_SAFE(mt->timers, timer, temp) {
                    
                    /* Delete from LL */
                    LL_DELETE(mt->timers, timer);
                    
                    /* Free memory inside single timer */
                    free(timer);
                }
            }

            chilog(TRACE, "Timer thread has successfully been killed");
            
            /* Properly deal w mutexes and condvar signals */
            pthread_mutex_unlock(&mt->cv_lock);
            pthread_mutex_lock(&mt->tt_lock);
            pthread_cond_signal(&mt->tt_cv);  
            pthread_mutex_unlock(&mt->tt_lock);
            pthread_exit(0);
        
        }

        chilog(TRACE, "Timer thread got out of wait status");

        /*  Note: This part of the loop can be triggered by spurious wakes
         *        and any calls of mt_set_timer, mt_cancel_timer that change 
         *        the head of the timers list. In these cases, no timer expires
         *        and only the wait time gets updated upon the next entry into
         *        this loop
         *  
         *  NOTE: This thread has locked cv_lock so no other thread can lock it
         *        until we return back to the waits, which unlock cv_lock
         */
        

        /* Check for expired timers; call their callbacks & reinsert them
           into the sorted timer list */
        chilog(TRACE, "Is any timer active? %d", any_timer_active);
        mt_chilog(DEBUG, mt, false);

        while (mt->timers->active) {

            /* Get current time and subtract it from first timer to expire */
            struct timespec now, diff;
            clock_gettime(CLOCK_REALTIME, &now);
            
            chilog(TRACE, "CURRENT TIME: <%lld> s <%lld> ns",
                     now.tv_sec, now.tv_nsec);

            timespec_subtract(&diff, &mt->timers->expiry_time, &now);
            
            /* If expiry time of the timer is past current time, timer expires */
            if (diff.tv_sec > 0 || diff.tv_sec == 0 && diff.tv_nsec > 0) {
                break;
            }

            single_timer_t *head = mt->timers;
            
            /* Call callback function, increment time_outs and expire timer */
            head->callback(mt, head, head->callback_args);
            head->num_timeouts += 1;
            head->active = false;
            
            chilog(DEBUG, "Expired timer <%d>", head->id);

            /* Reinsert inactive/expired timer into back of list */
            LL_DELETE(mt->timers, head);
            LL_INSERT_INORDER(mt->timers, head, compare_timers);       

        }

        /* Set wait_until_time to first timer's expiry time */      
        any_timer_active = mt->timers->active;
        
        if (any_timer_active) {
            wait_until_time = mt->timers->expiry_time;
            
            chilog(TRACE, "Set wait until time to <%lld> s <%lld> ns", 
                    wait_until_time.tv_sec, wait_until_time.tv_nsec);
        
        } else {
            /* Set wait_until_time to <now> as a default value */
            clock_gettime(CLOCK_REALTIME, &(wait_until_time));
        }
    }
    
    pthread_mutex_unlock(&mt->cv_lock);

    return NULL;
}
