#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>


const int BIGCOUNT = 1024;


static struct sembuf op_lock[2] = {
    2,       0,
    0, /* wait for [2] (lock) to equal 0 */
    2,       1,
    SEM_UNDO /* then increment [2] to 1 - this locks it */
             /* UNDO to release the lock if processes exits before explicitly unlocking */
};

static struct sembuf op_endcreate[2] = {
    1, -1, SEM_UNDO, /* decrement [1] (proc counter) with undo on exit */
                     /* UNDO to adjust proc counter if process exits before explicitly calling sem_close() */
    2, -1, SEM_UNDO  /* decrement [2] (lock) back to 0 -> unlock */
};

static struct sembuf op_open[1] = {
    1, -1, SEM_UNDO /* decrement [1] (proc counter) with undo on exit */
};

static struct sembuf op_close[3] = {
    2, 0, 0,        /* wait for [2] (lock) to equal 0 */
    2, 1, SEM_UNDO, /* then increment [2] to 1 - this locks it */
    1, 1, SEM_UNDO  /* then increment [1] (proc counter) */
};

static struct sembuf op_unlock[1] = {
    2, -1, SEM_UNDO /* decrement [2] (lock) back to 0 */
};

static struct sembuf op_op[1] = {
    0, 99, SEM_UNDO /* decrement or increment [0] with undo on exit */
                    /* the 99 is set to the actual amount to add or subtract (positive or negative) */
};

union semun {
    int val;
    semid_ds* buf;
    unsigned short* array;
};

int sem_create(key_t key, int initval);
void sem_rm(int id);
int sem_open(key_t key);
void sem_close(int id);
void sem_op(int id, int value);
void sem_wait(int id);
void sem_signal(int id);