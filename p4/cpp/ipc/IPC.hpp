#include <arpa/inet.h>
#include <memory.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>
#include <unordered_map>




class IPC {
    static const int FIFO_PERMS = 0666;
    static const std::string fifoPath;


   public:
    IPC();

    static bool setupIPC();
    static void closedIPC();

    static int readFromIPC();
    static bool writeToIPC(std::vector<float>& cnn1DInput, std::vector<float>& saeInput);
};
