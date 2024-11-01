#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>


#ifndef _SEM_H_
#define _SEM_H_
#include "sem.hpp"
#endif


using namespace std;


int sem_create(key_t key, int initval) {
    register int id, semval;
    if (key == IPC_PRIVATE)
        return -1; /* not intended for private semaphores */
    else if (key == (key_t)-1)
        return -1; /* probably an ftok() error by caller */
again:
    if ((id = semget(key, 3, 0666 | IPC_CREAT)) < 0) return (-1);
    if (semop(id, &op_lock[0], 2) < 0) {
        if (errno == EINVAL) {
            goto again;
        }
        cerr << "can't lock";
    }
    if ((semval = semctl(id, 1, GETVAL, 0)) < 0) {
        cerr << "can't GETVAL" << endl;
    }
    semun semctl_arg;
    if (semval == 0) {
        semctl_arg.val = initval;
        if (semctl(id, 0, SETVAL, semctl_arg) < 0) {
            cerr << "can't SETVAL[0]: " << strerror(errno) << endl;
        }
        semctl_arg.val = BIGCOUNT;
        if (semctl(id, 1, SETVAL, semctl_arg) < 0) {
            cerr << "can't SETVAL[1]: " << strerror(errno) << endl;
        }
    }
    if (semop(id, &op_endcreate[0], 2) < 0) {
        cerr << "can't end create" << endl;
    }
    return (id);
}


void sem_rm(int id) {
    if (semctl(id, 0, IPC_RMID, 0) < 0) {
        cerr << "can't IPC_RMID" << endl;
    }
}

int sem_open(key_t key) {
    register int id;
    if (key == IPC_PRIVATE) {
        return -1;
    } else if (key == (key_t)-1) {
        return -1;
    }
    if ((id = semget(key, 3, 0)) < 0) {
        return -1;
    } /* doesn't exist, or tables full */
    // Decrement the process counter. We don't need a lock to do this.
    if (semop(id, &op_open[0], 1) < 0) {
        cerr << "can't open" << endl;
    }
    return (id);
}

void sem_close(int id) {
    register int semval;
    // The following semop() first gets a lock on the semaphore,
    // then increments [1] - the process counter.
    if (semop(id, &op_close[0], 3) < 0) {
        cerr << "can't semop" << endl;
    }
    // if this is the last reference to the semaphore, remove this.
    if ((semval = semctl(id, 1, GETVAL, 0)) < 0) {
        cerr << "can't GETVAL" << endl;
    }
    if (semval > BIGCOUNT) {
        cerr << "sem[1] > BIGCOUNT" << endl;
    } else if (semval == BIGCOUNT) {
        sem_rm(id);
    } else if (semop(id, &op_unlock[0], 1) < 0) {
        cerr << "can't unlock" << endl; /* unlock */
    }
}

void sem_op(int id, int value) {
    if ((op_op[0].sem_op = value) == 0) {
        cerr << "can't have value == 0" << endl;
    }
    while (semop(id, &op_op[0], 1) < 0) {
        // cerr << "sem_op error" << endl;
    }
}

void sem_wait(int id) { sem_op(id, -1); }

void sem_signal(int id) { sem_op(id, 1); }