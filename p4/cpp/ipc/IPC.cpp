#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <ctime>
#include <sys/time.h>



#ifndef _SEM_H_
#define _SEM_H_
#include "sem.hpp"
#endif

#ifndef _IPC_H_
#define _IPC_H_
#include "IPC.hpp"
#endif

using namespace std;


const string IPC::fifoPath = "./pipe";



IPC::IPC() {}



bool IPC::setupIPC() {
    if (mknod(fifoPath.c_str(), S_IFIFO | FIFO_PERMS, 0) < 0) {
        cerr << "mknod() error! " << strerror(errno) << " " << errno << endl;
        return false;
    }

    return true;
}

int IPC::readFromIPC() {
    return open(fifoPath.c_str(), O_RDONLY);
}

bool IPC::writeToIPC(std::vector<float>& cnn1DInput, std::vector<float>& saeInput) {
    int size1 = cnn1DInput.size();
    int size2 = saeInput.size();

    int fd = open(fifoPath.c_str(), O_WRONLY);

    timeval startTime;
    gettimeofday(&startTime, NULL);

    write(fd, &startTime, sizeof(startTime));
    write(fd, &size1, sizeof(size1));
    write(fd, &size2, sizeof(size2));
    for (float value : cnn1DInput) {
        write(fd, &value, sizeof(value));
    }
    for (float value : saeInput) {
        write(fd, &value, sizeof(value));
    }
    close(fd);

    return true;
}


void IPC::closedIPC() { unlink(fifoPath.c_str()); }