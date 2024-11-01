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
#include <iostream>
#include <unordered_map>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif
#include <bf_switchd/bf_switchd.h>
#ifdef __cplusplus
}
#endif

/*
 * Convenient defines that reflect SDE conventions
 */
#ifndef SDE_INSTALL
#error "Please add -DSDE_INSTALL=\"$SDE_INSTALL\" to CPPFLAGS"
#endif

#define PROG_NAME "appClassification"
#define CONF_FILE_DIR "share/p4/targets/tofino"
#define CONF_FILE_PATH(prog) SDE_INSTALL "/" CONF_FILE_DIR "/" prog ".conf"

#define INIT_STATUS_TCP_PORT 7777

#define TV_PACKET_TYPE 3
#define SS_PACKET_TYPE 4



//------------------- global const variable ----------------------
#define VM_SIZE (4)
struct VM_info {
    uint32_t ip;
    uint16_t port;
};
const VM_info vms[VM_SIZE] = {{0x0a000101, 56},   // 10.0.1.1
                              {0x0a000102, 57},   // 10.0.1.2
                              {0x0a000103, 58},   // 10.0.1.3
                              {0x0a000201, 59}};  // 10.0.2.1

const uint16_t mirror_sid_1 = 5;
const uint16_t mirror_sid_2 = 6;
const uint16_t mirror_port_1 = 64;
const uint16_t mirror_port_2 = 316;

const uint16_t mirror_port_egress_queue = 0;
const uint64_t mirror_max_pkt_len = 136;  // 32bytes = 256 bit
#define SIZE_ETHERNET 14
//=================== global const variable ======================


// five tuple
class sniff_five_tuple_tv {  // the size of members must be divided by 8
   public:
    uint16_t session_id;
    uint16_t fwd_id;
    uint16_t bwd_id;

    uint16_t pkt_type;
    uint16_t reg_pkt_count;
    uint16_t reg_is_fwd;

    uint32_t tv_reg_fwd_iat;
    uint32_t tv_reg_bwd_iat;
    uint32_t tv_reg_fwd_total_iat;
    uint32_t tv_reg_bwd_total_iat;
    uint32_t tv_reg_fwd_min_iat;
    uint32_t tv_reg_bwd_min_iat;
    uint32_t tv_reg_fwd_max_iat;
    uint32_t tv_reg_bwd_max_iat;
    uint32_t tv_reg_fwd_var_iat;
    uint32_t tv_reg_bwd_var_iat;

    uint16_t tv_reg_fwd_ttl;
    uint16_t tv_reg_bwd_ttl;
    uint16_t tv_reg_fwd_total_ttl;
    uint16_t tv_reg_bwd_total_ttl;
    uint16_t tv_reg_fwd_min_ttl;
    uint16_t tv_reg_bwd_min_ttl;
    uint16_t tv_reg_fwd_max_ttl;
    uint16_t tv_reg_bwd_max_ttl;
    uint16_t tv_reg_fwd_var_ttl;
    uint16_t tv_reg_bwd_var_ttl;

    uint16_t tv_reg_fwd_pkt_size;
    uint16_t tv_reg_bwd_pkt_size;
    uint16_t tv_reg_fwd_total_pkt_size;
    uint16_t tv_reg_bwd_total_pkt_size;
    uint16_t tv_reg_fwd_min_pkt_size;
    uint16_t tv_reg_bwd_min_pkt_size;
    uint16_t tv_reg_fwd_max_pkt_size;
    uint16_t tv_reg_bwd_max_pkt_size;
    uint16_t tv_reg_fwd_var_pkt_size;
    uint16_t tv_reg_bwd_var_pkt_size;

    // uint16_t tv_reg_fwd_window;
    // uint16_t tv_reg_bwd_window;
    // uint16_t tv_reg_fwd_total_window;
    // uint16_t tv_reg_bwd_total_window;
    // uint16_t tv_reg_fwd_min_window;
    // uint16_t tv_reg_bwd_min_window;
    // uint16_t tv_reg_fwd_max_window;
    // uint16_t tv_reg_bwd_max_window;
    // uint16_t tv_reg_fwd_var_window;
    // uint16_t tv_reg_bwd_var_window;

    // uint8_t tv_fwd_is_rst_flag;
    // uint8_t tv_bwd_is_rst_flag;
    // uint8_t tv_fwd_is_keep_alive_ack;
    // uint8_t tv_bwd_is_keep_alive_ack;
    // uint8_t tv_is_keep_alive;
    // uint8_t tv_is_sync_flood;
};

class sniff_five_tuple_ss {  // the size of members must be divided by 8
   public:
    uint16_t session_id;
    uint16_t fwd_id;
    uint16_t bwd_id;

    uint16_t pkt_type;

    uint32_t sae_reg_total_iat;
    uint32_t sae_reg_min_iat;
    uint32_t sae_reg_max_iat;
    uint32_t sae_reg_mean_iat;
    // uint32_t sae_reg_var_iat;

    uint32_t sae_reg_session_connection_time;
    uint32_t sae_reg_irtt;
    uint16_t sae_reg_service_type;


    uint16_t sae_reg_total_pkt_size;
    uint16_t sae_reg_min_pkt_size;
    // uint16_t sae_reg_max_pkt_size;
    uint16_t sae_reg_mean_pkt_size;
    uint16_t sae_reg_var_pkt_size;

    // uint16_t sae_reg_total_ttl;
    // uint16_t sae_reg_min_ttl;
    // uint16_t sae_reg_max_ttl;
    // uint16_t sae_reg_mean_ttl;
    // uint16_t sae_reg_var_ttl;

    uint16_t sae_reg_total_window;
    uint16_t sae_reg_min_window;
    uint16_t sae_reg_max_window;
    uint16_t sae_reg_mean_window;
    uint16_t sae_reg_var_window;

    uint16_t sae_reg_total_l4_payload_size;
    uint16_t sae_reg_min_l4_payload_size;
    uint16_t sae_reg_max_l4_payload_size;
    uint16_t sae_reg_mean_l4_payload_size;
    uint16_t sae_reg_var_l4_payload_size;

    uint8_t sae_reg_total_is_rst_flag;
    uint8_t sae_reg_total_is_psh_flag;
    uint8_t sae_reg_total_is_keep_alive;
    // uint8_t sae_reg_total_is_keep_alive_ack;
    uint8_t sae_reg_total_is_sync_flood;
};


namespace bfrt {
namespace cia {
namespace appClassification {
namespace {
// Key field ids, table data field ids, action ids, Table object required for
// interacting with the table
const bfrt::BfRtInfo *bfrt_info = nullptr;
const bfrt::BfRtTable *ipv4_host_table_1 = nullptr;
const bfrt::BfRtTable *ipv4_host_table_2 = nullptr;
const bfrt::BfRtTable *mirror_table_1 = nullptr;
const bfrt::BfRtTable *mirror_table_2 = nullptr;
std::shared_ptr<bfrt::BfRtSession> session;

std::unique_ptr<bfrt::BfRtTableKey> ipv4_host_table_new_key_1;
std::unique_ptr<bfrt::BfRtTableKey> ipv4_host_table_new_key_2;
std::unique_ptr<bfrt::BfRtTableData> ipv4_host_table_new_data_1;
std::unique_ptr<bfrt::BfRtTableData> ipv4_host_table_new_data_2;


std::unique_ptr<bfrt::BfRtTableKey> mirror_table_new_key_1;
std::unique_ptr<bfrt::BfRtTableKey> mirror_table_new_key_2;
std::unique_ptr<bfrt::BfRtTableData> mirror_table_new_data_1;
std::unique_ptr<bfrt::BfRtTableData> mirror_table_new_data_2;

// Key field ids
bf_rt_id_t ipv4_host_table_ip_dst_key_id_1 = 0;
bf_rt_id_t ipv4_host_table_ip_dst_key_id_2 = 0;
bf_rt_id_t mirror_table_sid_key_id_1 = 0;
bf_rt_id_t mirror_table_sid_key_id_2 = 0;

// Action Ids
bf_rt_id_t ipv4_host_table_send_action_id_1 = 0;
bf_rt_id_t ipv4_host_table_send_action_id_2 = 0;
bf_rt_id_t mirror_table_normal_action_id_1 = 0;
bf_rt_id_t mirror_table_normal_action_id_2 = 0;
// Data field Ids for send action
bf_rt_id_t ipv4_host_table_send_action_port_field_id_1 = 0;
bf_rt_id_t ipv4_host_table_send_action_port_field_id_2 = 0;
bf_rt_id_t mirror_table_normal_action_direction_field_id_1 = 0;
bf_rt_id_t mirror_table_normal_action_direction_field_id_2 = 0;
bf_rt_id_t mirror_table_normal_action_session_enable_field_id_1 = 0;
bf_rt_id_t mirror_table_normal_action_session_enable_field_id_2 = 0;
bf_rt_id_t mirror_table_normal_action_ucast_egress_port_field_id_1 = 0;
bf_rt_id_t mirror_table_normal_action_ucast_egress_port_field_id_2 = 0;
bf_rt_id_t mirror_table_normal_action_ucast_egress_port_valid_field_id_1 = 0;
bf_rt_id_t mirror_table_normal_action_ucast_egress_port_valid_field_id_2 = 0;
bf_rt_id_t mirror_table_normal_action_egress_port_queue_field_id_1 = 0;
bf_rt_id_t mirror_table_normal_action_egress_port_queue_field_id_2 = 0;
bf_rt_id_t mirror_table_normal_action_max_pkt_len_field_id_1 = 0;
bf_rt_id_t mirror_table_normal_action_max_pkt_len_field_id_2 = 0;




// Device info.
#define ALL_PIPES 0xffff
bf_rt_target_t dev_tgt;
}  // anonymous namespace


// function prototype
void ipv4_host_table_send_action_add(uint32_t addr, uint16_t port);
void setUp();
void tableSetUp();
void mirror_table_cpu_entry();  //?

}  // namespace appClassification
}  // namespace cia
}  // namespace bfrt

void parse_options(bf_switchd_context_t *switchd_ctx, int argc, char **argv);
int app_run(bf_switchd_context_t *switchd_ctx);
int listening_cpu_port();
void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);