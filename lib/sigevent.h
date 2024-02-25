// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Quagga Signal handling header.
 *
 * Copyright (C) 2004 Paul Jakma.
 */

#ifndef _FRR_SIGNAL_H
#define _FRR_SIGNAL_H

#include <frrevent.h>

#include "frr_pthread.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FRR_SIGNAL_TIMER_INTERVAL 2L

struct frr_signal_t {
	int signal;	    /* signal number    */
	void (*handler)(void); /* handler to call  */

	volatile sig_atomic_t caught; /* private member   */
};

/* initialise sigevent system
 * takes:
 * - pointer to valid struct event_loop
 * - number of elements in passed in signals array
 * - array of frr_signal_t's describing signals to handle
 *   and handlers to use for each signal
 */
extern void signal_init(struct event_loop *m, int sigc,
			struct frr_signal_t *signals);

/* Check whether any signals have been received and are pending */
bool frr_sigevent_check(void);

/* check whether there are signals to handle, process any found */
extern int frr_sigevent_process(void);

/*
 * To decouple event_loop and signal handling, we run a dedicated thread
 * for signal catching.
 * 
 * The thread tries to catch the signals specified at signal_init(). Once
 * a signal is caught, this thread will inform the main thread of the coming
 * signal 
 * 
 * Why this decoupling is needed?
 * If both I/O and signal handling are undertaken by the main thread's
 * event_loop, to avoid race between signal handling and I/O polling,
 * pthread_sigmask has to be called by the event_loop frequently. 
 * However, it is noticed that pthread_sigmask causes unneglectable CPU
 * overhead. To solve this problem, we have to do decoupling here.
 */
void sigcatcher_pthread_run(struct event_loop *m);

/**
 * Entry function for signal catcher pthread.
 *
 * This function is in a loop-and-sleep style. Each time a signal
 * arrives, it wakes and notifies the caught signal to the main
 * pthread.
 *
 * @param arg pthread arg
 */
extern void *sigcatcher_start(void *arg);

/**
 * Stops the signal catcher thread and blocks until it terminates.
 */
int sigcatcher_stop(struct frr_pthread *fpt, void **result);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_SIGNAL_H */
