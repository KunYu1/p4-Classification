#include <vector>

#ifndef _IPC_H_
#define _IPC_H_
#include "../../ipc/IPC.hpp"
#endif

using namespace std;

int main() {
    for (int j = 0; j < 100; j++) {
        vector<float> a;
        vector<float> b;

        for (int i = 0; i < 10; i++) {
            a.push_back(i);
        }

        for (int i = 11; i < 23; i++) {
            b.push_back(i);
        }

        IPC::writeToIPC(a, b);
    }
}