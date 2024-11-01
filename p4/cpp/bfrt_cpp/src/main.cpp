#include <arpa/inet.h>
#include <getopt.h>
#include <math.h>
#include <pcap.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <exception>
#include <iostream>
#include <unordered_map>
#include <vector>


#ifndef _IPC_H_
#define _IPC_H_
#include "../../ipc/IPC.hpp"
#endif


#ifndef _BFRT_HPP_
#define _BFRT_HPP_
#include "bfrt.hpp"
#endif


bf_switchd_context_t *switchd_ctx;
void close_process_handler(int signum);

int main(int argc, char **argv) {
    signal(SIGINT, close_process_handler);


    // P4 Settings
    std::cout << "--------- Run P4 configuration ---------" << std::endl;
    if ((switchd_ctx = (bf_switchd_context_t *)calloc(1, sizeof(bf_switchd_context_t))) == NULL) {
        std::cout << "Cannot Allocate switchd context" << std::endl;
        exit(1);
    }

    switchd_ctx->install_dir = strdup(SDE_INSTALL);
    // switchd_ctx->conf_file = strdup(CONF_FILE_PATH(PROG_NAME));
    switchd_ctx->conf_file = strdup("/root/cia/samuel/p4-AppClassification/p4/initial_config/appClassification.conf.in");
    switchd_ctx->running_in_background = true;
    switchd_ctx->dev_sts_thread = true;
    switchd_ctx->dev_sts_port = INIT_STATUS_TCP_PORT;

    parse_options(switchd_ctx, argc, argv);
    bf_status_t status;

    // Do initial set up
    bfrt::cia::appClassification::setUp();
    // // Do table level set up
    bfrt::cia::appClassification::tableSetUp();

    system("bfshell -f /root/cia/samuel/p4-AppClassification/p4/initial_config/open_port_configuration.txt");
    // system("bfshell -b /root/cia/redduck/iotIDS/initial_config/bfrt_python_script.py"); // File already exists in
    // database: bfruntime.proto
    std::cout << "========= P4 configuration end =========" << std::endl;




    std::cerr << "--------- start to listening cpu port ---------" << std::endl;
    listening_cpu_port();

    status = app_run(switchd_ctx);

    if (switchd_ctx) free(switchd_ctx);

    return status;
}


void close_process_handler(int signum) {
    std::cout << "Caught signal" << signum << std::endl;
    std::cout << "close program" << std::endl;

    system("bfshell -f /root/cia/samuel/p4-AppClassification/initial_config/close_port_configuration.txt");
    sleep(2);
    if (switchd_ctx) free(switchd_ctx);

    exit(signum);
}