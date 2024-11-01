#include <arpa/inet.h>
#include <bf_rt/bf_rt_common.h>
#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>

#include <array>
#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_table.hpp>
#include <bf_rt/bf_rt_table_data.hpp>
#include <bf_rt/bf_rt_table_key.hpp>
#include <bf_rt_mirror/bf_rt_mirror_table_data_impl.hpp>
#include <bf_rt_mirror/bf_rt_mirror_table_impl.hpp>
#include <bf_rt_mirror/bf_rt_mirror_table_key_impl.hpp>
#include <cmath>
#include <ctime>
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


namespace bfrt {
namespace cia {
namespace appClassification {

// This function does the initial setUp of getting bfrtInfo object associated
// with the P4 program from which all other required objects are obtained
void setUp() {
    dev_tgt.dev_id = 0;
    dev_tgt.pipe_id = ALL_PIPES;
    // Get devMgr singleton instance
    auto &dev_mgr = bfrt::BfRtDevMgr::getInstance();

    // Get bfrtInfo object from dev_id and p4 program name
    auto bf_status = dev_mgr.bfRtInfoGet(dev_tgt.dev_id, "appClassification", &bfrt_info);
    // Check for status
    assert(bf_status == BF_SUCCESS);

    // Create a session object
    session = bfrt::BfRtSession::sessionCreate();
}

void tableSetUp() {
    // std::vector<const BfRtTable *> tt;
    // bfrt_info->bfrtInfoGetTables(&tt);
    // for (auto tmp : tt) {
    //   std::string str;
    //   tmp->tableNameGet(&str);
    //   std::cout << str << std::endl;
    // }

    // Get table object from name
    bf_status_t bf_status;

    bf_status = bfrt_info->bfrtTableFromNameGet("Ingress_1.ipv4_host", &ipv4_host_table_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrt_info->bfrtTableFromNameGet("Ingress_2.ipv4_host", &ipv4_host_table_2);
    assert(bf_status == BF_SUCCESS);

    bf_status = bfrt_info->bfrtTableFromNameGet("$mirror.cfg", &mirror_table_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrt_info->bfrtTableFromNameGet("$mirror.cfg", &mirror_table_2);
    assert(bf_status == BF_SUCCESS);

    // initialize register value (test)
    // const BfRtTable *reg1;
    // bf_status = bfrt_info->bfrtTableFromNameGet("pipe.Ingress.sae_reg_max_window", &reg1);
    // assert(bf_status == BF_SUCCESS);
    // bf_status = reg1->tableClear(*session, dev_tgt);
    // assert(bf_status == BF_SUCCESS);



    // Get action Ids for hit and miss actions
    bf_status = ipv4_host_table_1->actionIdGet("Ingress_1.send", &ipv4_host_table_send_action_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_2->actionIdGet("Ingress_2.send", &ipv4_host_table_send_action_id_2);
    assert(bf_status == BF_SUCCESS);

    bf_status = mirror_table_1->actionIdGet("$normal", &mirror_table_normal_action_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->actionIdGet("$normal", &mirror_table_normal_action_id_2);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field and data fields
    bf_status = ipv4_host_table_1->keyFieldIdGet("hdr.ipv4.dst_addr", &ipv4_host_table_ip_dst_key_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_2->keyFieldIdGet("hdr.ipv4.dst_addr", &ipv4_host_table_ip_dst_key_id_2);
    assert(bf_status == BF_SUCCESS);

    bf_status = mirror_table_1->keyFieldIdGet("$sid", &mirror_table_sid_key_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->keyFieldIdGet("$sid", &mirror_table_sid_key_id_2);
    assert(bf_status == BF_SUCCESS);

    /***********************************************************************
     * DATA FIELD ID GET FOR "ipv4_host_table_send" ACTION
     **********************************************************************/
    bf_status = ipv4_host_table_1->dataFieldIdGet("port", ipv4_host_table_send_action_id_1,
                                                  &ipv4_host_table_send_action_port_field_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_2->dataFieldIdGet("port", ipv4_host_table_send_action_id_2,
                                                  &ipv4_host_table_send_action_port_field_id_2);
    assert(bf_status == BF_SUCCESS);

    /***********************************************************************
     * DATA FIELD ID GET FOR "normal" ACTION
     **********************************************************************/
    bf_status = mirror_table_1->dataFieldIdGet("$direction", mirror_table_normal_action_id_1,
                                               &mirror_table_normal_action_direction_field_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_1->dataFieldIdGet("$session_enable", mirror_table_normal_action_id_1,
                                               &mirror_table_normal_action_session_enable_field_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_1->dataFieldIdGet("$ucast_egress_port", mirror_table_normal_action_id_1,
                                               &mirror_table_normal_action_ucast_egress_port_field_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_1->dataFieldIdGet("$ucast_egress_port_valid", mirror_table_normal_action_id_1,
                                               &mirror_table_normal_action_ucast_egress_port_valid_field_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_1->dataFieldIdGet("$egress_port_queue", mirror_table_normal_action_id_1,
                                               &mirror_table_normal_action_egress_port_queue_field_id_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_1->dataFieldIdGet("$max_pkt_len", mirror_table_normal_action_id_1,
                                               &mirror_table_normal_action_max_pkt_len_field_id_1);
    assert(bf_status == BF_SUCCESS);


    bf_status = mirror_table_2->dataFieldIdGet("$direction", mirror_table_normal_action_id_2,
                                               &mirror_table_normal_action_direction_field_id_2);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->dataFieldIdGet("$session_enable", mirror_table_normal_action_id_2,
                                               &mirror_table_normal_action_session_enable_field_id_2);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->dataFieldIdGet("$ucast_egress_port", mirror_table_normal_action_id_2,
                                               &mirror_table_normal_action_ucast_egress_port_field_id_2);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->dataFieldIdGet("$ucast_egress_port_valid", mirror_table_normal_action_id_2,
                                               &mirror_table_normal_action_ucast_egress_port_valid_field_id_2);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->dataFieldIdGet("$egress_port_queue", mirror_table_normal_action_id_2,
                                               &mirror_table_normal_action_egress_port_queue_field_id_2);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->dataFieldIdGet("$max_pkt_len", mirror_table_normal_action_id_2,
                                               &mirror_table_normal_action_max_pkt_len_field_id_2);
    assert(bf_status == BF_SUCCESS);


    // Allocate key and data once, and use reset across different uses
    bf_status = ipv4_host_table_1->keyAllocate(&ipv4_host_table_new_key_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_2->keyAllocate(&ipv4_host_table_new_key_2);
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_1->dataAllocate(&ipv4_host_table_new_data_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_2->dataAllocate(&ipv4_host_table_new_data_2);
    assert(bf_status == BF_SUCCESS);

    bf_status = mirror_table_1->keyAllocate(&mirror_table_new_key_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->keyAllocate(&mirror_table_new_key_2);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_1->dataAllocate(&mirror_table_new_data_1);
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->dataAllocate(&mirror_table_new_data_2);
    assert(bf_status == BF_SUCCESS);

    // add default entries
    for (int i = 0; i < VM_SIZE; i++) ipv4_host_table_send_action_add(vms[i].ip, vms[i].port);
    mirror_table_cpu_entry();
}  // tableSetUp()

void mirror_table_cpu_entry() {
    // Reset key and data
    bf_status_t bf_status;

    bf_status = mirror_table_1->keyReset(mirror_table_new_key_1.get());
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_1->dataReset(mirror_table_normal_action_id_1, mirror_table_new_data_1.get());
    assert(bf_status == BF_SUCCESS);

    bf_status = mirror_table_2->keyReset(mirror_table_new_key_2.get());
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_2->dataReset(mirror_table_normal_action_id_2, mirror_table_new_data_2.get());
    assert(bf_status == BF_SUCCESS);

    // Set key
    bf_status = mirror_table_new_key_1->setValue(mirror_table_sid_key_id_1, static_cast<uint16_t>(mirror_sid_1));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_key_2->setValue(mirror_table_sid_key_id_2, static_cast<uint16_t>(mirror_sid_2));
    assert(bf_status == BF_SUCCESS);

    // Set data
    bf_status = mirror_table_new_data_1->setValue(mirror_table_normal_action_direction_field_id_1,
                                                  static_cast<std::string>("BOTH"));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_1->setValue(mirror_table_normal_action_session_enable_field_id_1,
                                                  static_cast<bool>(true));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_1->setValue(mirror_table_normal_action_ucast_egress_port_field_id_1,
                                                  static_cast<uint64_t>(mirror_port_1));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_1->setValue(mirror_table_normal_action_ucast_egress_port_valid_field_id_1,
                                                  static_cast<bool>(true));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_1->setValue(mirror_table_normal_action_egress_port_queue_field_id_1,
                                                  static_cast<uint64_t>(mirror_port_egress_queue));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_1->setValue(mirror_table_normal_action_max_pkt_len_field_id_1,
                                                  static_cast<uint64_t>(mirror_max_pkt_len));
    assert(bf_status == BF_SUCCESS);

    bf_status = mirror_table_1->tableEntryAdd(*session, dev_tgt, *mirror_table_new_key_1, *mirror_table_new_data_1);
    assert(bf_status == BF_SUCCESS);


    bf_status = mirror_table_new_data_2->setValue(mirror_table_normal_action_direction_field_id_2,
                                                  static_cast<std::string>("BOTH"));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_2->setValue(mirror_table_normal_action_session_enable_field_id_2,
                                                  static_cast<bool>(true));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_2->setValue(mirror_table_normal_action_ucast_egress_port_field_id_2,
                                                  static_cast<uint64_t>(mirror_port_2));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_2->setValue(mirror_table_normal_action_ucast_egress_port_valid_field_id_2,
                                                  static_cast<bool>(true));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_2->setValue(mirror_table_normal_action_egress_port_queue_field_id_2,
                                                  static_cast<uint64_t>(mirror_port_egress_queue));
    assert(bf_status == BF_SUCCESS);
    bf_status = mirror_table_new_data_2->setValue(mirror_table_normal_action_max_pkt_len_field_id_2,
                                                  static_cast<uint64_t>(mirror_max_pkt_len));
    assert(bf_status == BF_SUCCESS);

    bf_status = mirror_table_2->tableEntryAdd(*session, dev_tgt, *mirror_table_new_key_2, *mirror_table_new_data_2);
    assert(bf_status == BF_SUCCESS);
}

void ipv4_host_table_send_action_add(uint32_t addr, uint16_t port) {
    // Reset key and data
    bf_status_t bf_status;

    bf_status = ipv4_host_table_1->keyReset(ipv4_host_table_new_key_1.get());
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_2->keyReset(ipv4_host_table_new_key_2.get());
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_1->dataReset(ipv4_host_table_send_action_id_1, ipv4_host_table_new_data_1.get());
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_2->dataReset(ipv4_host_table_send_action_id_2, ipv4_host_table_new_data_2.get());
    assert(bf_status == BF_SUCCESS);

    // Set key and data
    bf_status = ipv4_host_table_new_key_1->setValue(ipv4_host_table_ip_dst_key_id_1, static_cast<uint64_t>(addr));
    assert(bf_status == BF_SUCCESS);
    bf_status = ipv4_host_table_new_key_2->setValue(ipv4_host_table_ip_dst_key_id_2, static_cast<uint64_t>(addr));
    assert(bf_status == BF_SUCCESS);
    bf_status =
        ipv4_host_table_new_data_1->setValue(ipv4_host_table_send_action_port_field_id_1, static_cast<uint64_t>(port));
    assert(bf_status == BF_SUCCESS);
    bf_status =
        ipv4_host_table_new_data_2->setValue(ipv4_host_table_send_action_port_field_id_2, static_cast<uint64_t>(port));
    assert(bf_status == BF_SUCCESS);

    bf_status =
        ipv4_host_table_1->tableEntryAdd(*session, dev_tgt, *ipv4_host_table_new_key_1, *ipv4_host_table_new_data_1);
    assert(bf_status == BF_SUCCESS);
    bf_status =
        ipv4_host_table_2->tableEntryAdd(*session, dev_tgt, *ipv4_host_table_new_key_2, *ipv4_host_table_new_data_2);
    assert(bf_status == BF_SUCCESS);
}

}  // namespace appClassification
}  // namespace cia
}  // namespace bfrt

void parse_options(bf_switchd_context_t *switchd_ctx, int argc, char **argv) {
    int option_index = 0;
    enum opts {
        OPT_INSTALLDIR = 1,
        OPT_CONFFILE,
    };
    static struct option options[] = {{"help", no_argument, 0, 'h'},
                                      {"install-dir", required_argument, 0, OPT_INSTALLDIR},
                                      {"conf-file", required_argument, 0, OPT_CONFFILE}};

    while (1) {
        int c = getopt_long(argc, argv, "h", options, &option_index);

        if (c == -1) {
            break;
        }
        switch (c) {
            case OPT_INSTALLDIR:
                switchd_ctx->install_dir = strdup(optarg);
                std::cout << "Install Dir: " << switchd_ctx->install_dir << std::endl;
                break;
            case OPT_CONFFILE:
                switchd_ctx->conf_file = strdup(optarg);
                std::cout << "Conf-file : " << switchd_ctx->conf_file << std::endl;
                break;
            case 'h':
            case '?':
                std::cout << "tna_idletimeout" << std::endl;
                std::cout << "Usage : tna_idletimeout --install-dir=path to where the SDE is "
                             "installed"
                          << std::endl;
                exit(c == 'h' ? 0 : 1);
                break;
            default:
                std::cout << "Invalid option" << std::endl;
                exit(0);
                break;
        }
    }
    if (switchd_ctx->install_dir == NULL) {
        std::cout << "ERROR : --install-dir must be specified" << std::endl;
        exit(0);
    }

    if (switchd_ctx->conf_file == NULL) {
        std::cout << "ERROR : --conf-file must be specified" << std::endl;
        exit(0);
    }
}


int app_run(bf_switchd_context_t *switchd_ctx) {
    (void)switchd_ctx;

    /* Run Indefinitely */
    while (true) {
        sleep(1);
    }
}

std::unordered_map<int, std::vector<sniff_five_tuple_tv *>> flows;

int counter = 0;
void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // std::cout << counter++ << " Pkt Recv" << std::endl;

    clock_t startTime, endTime;
    startTime = clock();

    sniff_five_tuple_tv *f_tuple_tv;
    sniff_five_tuple_tv *f_tuple_tv_new = new sniff_five_tuple_tv;
    sniff_five_tuple_ss *f_tuple_ss;

    f_tuple_tv = (struct sniff_five_tuple_tv *)(packet + SIZE_ETHERNET);
    f_tuple_ss = (struct sniff_five_tuple_ss *)(packet + SIZE_ETHERNET);

    // std::cout << "Copy Memory Start" << std::endl;

    memcpy(f_tuple_tv_new, f_tuple_tv, sizeof(sniff_five_tuple_tv));

    // std::cout << "Copy Memory Complete" << std::endl;

    // std::cout << "type: " << ntohs(f_tuple_tv->pkt_type) << std::endl;

    if (ntohs(f_tuple_tv->pkt_type) == TV_PACKET_TYPE) {
        std::cout << "type TV_PACKET_TYPE" << std::endl;

        if (ntohs(f_tuple_tv->reg_pkt_count) == 0) {
            std::cout << counter++ << " Flow Recv" << std::endl;
            flows[(int)ntohs(f_tuple_tv->session_id)] = std::vector<sniff_five_tuple_tv *>();
            flows[(int)ntohs(f_tuple_tv->session_id)].reserve(8);
        }

        if ((int)ntohs(f_tuple_tv->reg_pkt_count) < 8) {
            flows[(int)ntohs(f_tuple_tv->session_id)].push_back(f_tuple_tv_new);
            std::cout << "Input Entry " << ntohs(f_tuple_tv_new->session_id) << std::endl;
            std::cout << "session_id: " << ntohs(f_tuple_tv_new->session_id) << std::endl;
            std::cout << "fwd_id: " << ntohs(f_tuple_tv_new->fwd_id) << std::endl;
            std::cout << "bwd_id: " << ntohs(f_tuple_tv_new->bwd_id) << std::endl;
            std::cout << "is_fwd: " << ntohs(f_tuple_tv_new->reg_is_fwd) << std::endl;
            std::cout << "pkt_count: " << ntohs(f_tuple_tv_new->reg_pkt_count) << "\n\n";
        }

    } else if (ntohs(f_tuple_ss->pkt_type) == SS_PACKET_TYPE) {
        std::cout << "type SS_PACKET_TYPE" << std::endl;

        std::vector<float> cnn1DInput;
        std::vector<float> saeInput;

        // std::cout << "Create vector complete" << std::endl;
        std::cout << (int)ntohs(f_tuple_ss->session_id) << std::endl;
        std::cout << (flows.find((int)ntohs(f_tuple_ss->session_id)) != flows.end()) << std::endl;

        if (flows.find((int)ntohs(f_tuple_ss->session_id)) != flows.end() && flows[(int)ntohs(f_tuple_ss->session_id)].size() == 8) {
            for (auto tv_pkt : flows[(int)ntohs(f_tuple_ss->session_id)]) {
                std::cout << "session_id: " << ntohs(tv_pkt->session_id) << std::endl;
                std::cout << "pkt_count: " << ntohs(tv_pkt->reg_pkt_count) << std::endl;

                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_total_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_total_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_min_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_min_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_max_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_max_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_var_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_var_pkt_size)));

                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_total_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_total_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_var_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_var_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_min_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_min_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_max_iat)) * pow(10, -6));
                cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_max_iat)) * pow(10, -6));

                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_total_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_total_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_min_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_min_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_max_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_max_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_var_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_var_ttl)));
            }


            std::cout << "ss_session_id: " << ntohs(f_tuple_ss->session_id) << std::endl;
            std::cout << "ss_fwd_id: " << ntohs(f_tuple_ss->fwd_id) << std::endl;
            std::cout << "ss_bwd_id: " << ntohs(f_tuple_ss->bwd_id) << std::endl;
            std::cout.flush();



            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_total_pkt_size)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_mean_pkt_size)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_var_pkt_size)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_min_pkt_size)));
            saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_total_iat)) * pow(10, -6));
            saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_mean_iat)) * pow(10, -6));
            saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_min_iat)) * pow(10, -6));
            saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_max_iat)) * pow(10, -6));
            saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_session_connection_time)) * pow(10, -6));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_service_type)));
            saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_irtt)) * pow(10, 3));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_total_window)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_mean_window)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_var_window)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_min_window)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_max_window)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_total_l4_payload_size)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_mean_l4_payload_size)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_var_l4_payload_size)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_min_l4_payload_size)));
            saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_max_l4_payload_size)));
            saeInput.push_back(float(unsigned(f_tuple_ss->sae_reg_total_is_rst_flag)));
            saeInput.push_back(float(unsigned(f_tuple_ss->sae_reg_total_is_psh_flag)));
            saeInput.push_back(float(unsigned(f_tuple_ss->sae_reg_total_is_keep_alive)));
            saeInput.push_back(float(unsigned(f_tuple_ss->sae_reg_total_is_sync_flood)));

            IPC::writeToIPC(cnn1DInput, saeInput);

            endTime = clock();
            std::cout << "Time = " << double(endTime - startTime) / CLOCKS_PER_SEC << "s" << std::endl;
        }
    }


    if (ntohs(f_tuple_tv->pkt_type) == TV_PACKET_TYPE) {
        // std::cout << std::endl;
        // std::cout << "session_id: " << ntohs(f_tuple_tv->session_id) << std::endl;
        // std::cout << "fwd_id: " << ntohs(f_tuple_tv->fwd_id) << std::endl;
        // std::cout << "bwd_id: " << ntohs(f_tuple_tv->bwd_id) << std::endl;

        // std::cout << "pkt_type: " << ntohs(f_tuple_tv->pkt_type) << std::endl;
        // std::cout << "pkt_count: " << ntohs(f_tuple_tv->reg_pkt_count) << std::endl;
        // std::cout << "is_fwd: " << ntohs(f_tuple_tv->reg_is_fwd) << std::endl;

        // std::cout << "fwd_iat: " << ntohl(f_tuple_tv->tv_reg_fwd_iat) << std::endl;
        // std::cout << "bwd_iat: " << ntohl(f_tuple_tv->tv_reg_bwd_iat) << std::endl;
        // std::cout << "fwd_total_iat: " << ntohl(f_tuple_tv->tv_reg_fwd_total_iat) << std::endl;
        // std::cout << "bwd_total_iat: " << ntohl(f_tuple_tv->tv_reg_bwd_total_iat) << std::endl;
        // std::cout << "fwd_min_iat: " << ntohl(f_tuple_tv->tv_reg_fwd_min_iat) << std::endl;
        // std::cout << "bwd_min_iat: " << ntohl(f_tuple_tv->tv_reg_bwd_min_iat) << std::endl;
        // std::cout << "fwd_max_iat: " << ntohl(f_tuple_tv->tv_reg_fwd_max_iat) << std::endl;
        // std::cout << "bwd_max_iat: " << ntohl(f_tuple_tv->tv_reg_bwd_max_iat) << std::endl;
        // std::cout << "fwd_var_iat: " << ntohl(f_tuple_tv->tv_reg_fwd_var_iat) << std::endl;
        // std::cout << "bwd_var_iat: " << ntohl(f_tuple_tv->tv_reg_bwd_var_iat) << std::endl;

        // std::cout << "fwd_ttl: " << ntohs(f_tuple_tv->tv_reg_fwd_ttl) << std::endl;
        // std::cout << "bwd_ttl: " << ntohs(f_tuple_tv->tv_reg_bwd_ttl) << std::endl;
        // std::cout << "fwd_total_ttl: " << ntohs(f_tuple_tv->tv_reg_fwd_total_ttl) << std::endl;
        // std::cout << "bwd_total_ttl: " << ntohs(f_tuple_tv->tv_reg_bwd_total_ttl) << std::endl;
        // std::cout << "fwd_min_ttl: " << ntohs(f_tuple_tv->tv_reg_fwd_min_ttl) << std::endl;
        // std::cout << "bwd_min_ttl: " << ntohs(f_tuple_tv->tv_reg_bwd_min_ttl) << std::endl;
        // std::cout << "fwd_max_ttl: " << ntohs(f_tuple_tv->tv_reg_fwd_max_ttl) << std::endl;
        // std::cout << "bwd_max_ttl: " << ntohs(f_tuple_tv->tv_reg_bwd_max_ttl) << std::endl;
        // std::cout << "fwd_var_ttl: " << ntohs(f_tuple_tv->tv_reg_fwd_var_ttl) << std::endl;
        // std::cout << "bwd_var_ttl: " << ntohs(f_tuple_tv->tv_reg_bwd_var_ttl) << std::endl;

        // std::cout << "fwd_pkt_size: " << ntohs(f_tuple_tv->tv_reg_fwd_pkt_size) << std::endl;
        // std::cout << "bwd_pkt_size: " << ntohs(f_tuple_tv->tv_reg_bwd_pkt_size) << std::endl;
        // std::cout << "fwd_total_pkt_size: " << ntohs(f_tuple_tv->tv_reg_fwd_total_pkt_size) << std::endl;
        // std::cout << "bwd_total_pkt_size: " << ntohs(f_tuple_tv->tv_reg_bwd_total_pkt_size) << std::endl;
        // std::cout << "fwd_min_pkt_size: " << ntohs(f_tuple_tv->tv_reg_fwd_min_pkt_size) << std::endl;
        // std::cout << "bwd_min_pkt_size: " << ntohs(f_tuple_tv->tv_reg_bwd_min_pkt_size) << std::endl;
        // std::cout << "fwd_max_pkt_size: " << ntohs(f_tuple_tv->tv_reg_fwd_max_pkt_size) << std::endl;
        // std::cout << "bwd_max_pkt_size: " << ntohs(f_tuple_tv->tv_reg_bwd_max_pkt_size) << std::endl;
        // std::cout << "fwd_var_pkt_size: " << ntohs(f_tuple_tv->tv_reg_fwd_var_pkt_size) << std::endl;
        // std::cout << "bwd_var_pkt_size: " << ntohs(f_tuple_tv->tv_reg_bwd_var_pkt_size) << std::endl;

        //     std::cout << "fwd_window: " << ntohs(f_tuple_tv->tv_reg_fwd_window) << std::endl;
        //     std::cout << "bwd_window: " << ntohs(f_tuple_tv->tv_reg_bwd_window) << std::endl;
        //     // std::cout << "fwd_total_window: " << ntohs(f_tuple_tv->tv_reg_fwd_total_window) << std::endl;
        //     // std::cout << "bwd_total_window: " << ntohs(f_tuple_tv->tv_reg_bwd_total_window) << std::endl;
        //     std::cout << "fwd_min_window: " << ntohs(f_tuple_tv->tv_reg_fwd_min_window) << std::endl;
        //     std::cout << "bwd_min_window: " << ntohs(f_tuple_tv->tv_reg_bwd_min_window) << std::endl;
        //     // std::cout << "fwd_max_window: " << ntohs(f_tuple_tv->tv_reg_fwd_max_window) << std::endl;
        //     // std::cout << "bwd_max_window: " << ntohs(f_tuple_tv->tv_reg_bwd_max_window) << std::endl;
        //     std::cout << "fwd_var_window: " << ntohs(f_tuple_tv->tv_reg_fwd_var_window) << std::endl;
        //     std::cout << "bwd_var_window: " << ntohs(f_tuple_tv->tv_reg_bwd_var_window) << std::endl;

        //     std::cout << "fwd_is_rst_flag: " << unsigned(f_tuple_tv->tv_fwd_is_rst_flag) << std::endl;
        //     std::cout << "bwd_is_rst_flag: " << unsigned(f_tuple_tv->tv_bwd_is_rst_flag) << std::endl;
        //     // std::cout << "fwd_is_keep_alive_ack: " << unsigned(f_tuple_tv->tv_fwd_is_keep_alive_ack) << std::endl;
        //     // std::cout << "bwd_is_keep_alive_ack: " << unsigned(f_tuple_tv->tv_bwd_is_keep_alive_ack) << std::endl;
        //     std::cout << "is_keep_alive: " << unsigned(f_tuple_tv->tv_is_keep_alive) << std::endl;
        //     std::cout << "is_sync_flood: " << unsigned(f_tuple_tv->tv_is_sync_flood) << std::endl;

        //     std::cout << std::endl;
        std::cout << std::endl;


    } else if (ntohs(f_tuple_ss->pkt_type) == SS_PACKET_TYPE) {
        //     std::cout << std::endl;
        //     std::cout << "session_id: " << ntohs(f_tuple_ss->session_id) << std::endl;
        //     std::cout << "fwd_id: " << ntohs(f_tuple_ss->fwd_id) << std::endl;
        //     std::cout << "bwd_id: " << ntohs(f_tuple_ss->bwd_id) << std::endl;

        //     std::cout << "pkt_type: " << ntohs(f_tuple_ss->pkt_type) << std::endl;


        //     std::cout << "total_iat: " << ntohl(f_tuple_ss->sae_reg_total_iat) << std::endl;
        //     std::cout << "min_iat: " << ntohl(f_tuple_ss->sae_reg_min_iat) << std::endl;
        //     std::cout << "max_iat: " << ntohl(f_tuple_ss->sae_reg_max_iat) << std::endl;
        //     std::cout << "mean_iat: " << ntohl(f_tuple_ss->sae_reg_mean_iat) << std::endl;
        //     // std::cout << "var_iat: " << ntohl(f_tuple_ss->sae_reg_var_iat) << std::endl;

        //     std::cout << "session_connection_time: " << ntohl(f_tuple_ss->sae_reg_session_connection_time) << std::endl;
        //     std::cout << "irtt: " << ntohl(f_tuple_ss->sae_reg_irtt) << std::endl;
        //     std::cout << "service_type: " << ntohs(f_tuple_ss->sae_reg_service_type) << std::endl;

        //     std::cout << "total_pkt_size: " << ntohs(f_tuple_ss->sae_reg_total_pkt_size) << std::endl;
        //     std::cout << "min_pkt_size: " << ntohs(f_tuple_ss->sae_reg_min_pkt_size) << std::endl;
        //     // std::cout << "max_pkt_size: " << ntohs(f_tuple_ss->sae_reg_max_pkt_size) << std::endl;
        //     std::cout << "mean_pkt_size: " << ntohs(f_tuple_ss->sae_reg_mean_pkt_size) << std::endl;
        //     std::cout << "var_pkt_size: " << ntohs(f_tuple_ss->sae_reg_var_pkt_size) << std::endl;

        //     // std::cout << "total_ttl: " << ntohs(f_tuple_ss->sae_reg_total_ttl) << std::endl;
        //     // std::cout << "min_ttl: " << ntohs(f_tuple_ss->sae_reg_min_ttl) << std::endl;
        //     // std::cout << "max_ttl: " << ntohs(f_tuple_ss->sae_reg_max_ttl) << std::endl;
        //     // std::cout << "mean_ttl: " << ntohs(f_tuple_ss->sae_reg_mean_ttl) << std::endl;
        //     // std::cout << "var_ttl: " << ntohs(f_tuple_ss->sae_reg_var_ttl) << std::endl;

        //     std::cout << "total_window: " << ntohs(f_tuple_ss->sae_reg_total_window) << std::endl;
        //     std::cout << "min_window: " << ntohs(f_tuple_ss->sae_reg_min_window) << std::endl;
        //     std::cout << "max_window: " << ntohs(f_tuple_ss->sae_reg_max_window) << std::endl;
        //     std::cout << "mean_window: " << ntohs(f_tuple_ss->sae_reg_mean_window) << std::endl;
        //     std::cout << "var_window: " << ntohs(f_tuple_ss->sae_reg_var_window) << std::endl;

        //     std::cout << "total_l4_payload_size: " << ntohs(f_tuple_ss->sae_reg_total_l4_payload_size) << std::endl;
        //     std::cout << "min_l4_payload_size: " << ntohs(f_tuple_ss->sae_reg_min_l4_payload_size) << std::endl;
        //     std::cout << "max_l4_payload_size: " << ntohs(f_tuple_ss->sae_reg_max_l4_payload_size) << std::endl;
        //     std::cout << "mean_l4_payload_size: " << ntohs(f_tuple_ss->sae_reg_mean_l4_payload_size) << std::endl;
        //     std::cout << "var_l4_payload_size: " << ntohs(f_tuple_ss->sae_reg_var_l4_payload_size) << std::endl;

        //     std::cout << "total_is_rst_flag: " << unsigned(f_tuple_ss->sae_reg_total_is_rst_flag) << std::endl;
        //     std::cout << "total_is_psh_flag: " << unsigned(f_tuple_ss->sae_reg_total_is_psh_flag) << std::endl;
        //     std::cout << "total_is_keep_alive: " << unsigned(f_tuple_ss->sae_reg_total_is_keep_alive) << std::endl;
        //     // std::cout << "total_is_keep_alive_ack: " << unsigned(f_tuple_ss->sae_reg_total_is_keep_alive_ack) <<
        //     std::endl; std::cout << "total_is_sync_flood: " << unsigned(f_tuple_ss->sae_reg_total_is_sync_flood) << std::endl;

        //     std::cout << std::endl;
        std::cout << std::endl;
    }
}


int listening_cpu_port() {
    std::string dev = "enp4s0f1";
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    descr = pcap_open_live(dev.c_str(), mirror_max_pkt_len, 1, -1, errbuf);  // 65535最大，表示不切割封包
    if (descr == NULL) {
        std::cout << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    if (pcap_loop(descr, -1, packet_handler, NULL) < 0) {
        std::cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    return 0;
}
