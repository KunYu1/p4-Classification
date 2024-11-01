#include <arpa/inet.h>
#include <getopt.h>
//#include <pcap.h>
#include <signal.h>
#include <unistd.h>

#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>

#include <grpcpp/grpcpp.h>
#include "p4/v1/p4runtime.pb.h"
#include "p4/v1/p4runtime.grpc.pb.h"

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

    // uint32_t tv_reg_fwd_iat;
    // uint32_t tv_reg_bwd_iat;
    // uint32_t tv_reg_fwd_total_iat;
    // uint32_t tv_reg_bwd_total_iat;
    // uint32_t tv_reg_fwd_min_iat;
    // uint32_t tv_reg_bwd_min_iat;
    // uint32_t tv_reg_fwd_max_iat;
    // uint32_t tv_reg_bwd_max_iat;
    // uint32_t tv_reg_fwd_var_iat;
    // uint32_t tv_reg_bwd_var_iat;

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
};

class sniff_five_tuple_ss {  // the size of members must be divided by 8
   public:
    uint16_t session_id;
    uint16_t fwd_id;
    uint16_t bwd_id;

    uint16_t pkt_type;

    // uint32_t sae_reg_total_iat;
    // uint32_t sae_reg_min_iat;
    // uint32_t sae_reg_max_iat;
    // uint32_t sae_reg_mean_iat;

    // uint32_t sae_reg_session_connection_time;
    uint32_t sae_reg_irtt;
    uint16_t sae_reg_service_type;

    uint16_t sae_reg_total_pkt_size;
    uint16_t sae_reg_min_pkt_size;
    uint16_t sae_reg_mean_pkt_size;
    uint16_t sae_reg_var_pkt_size;

    uint32_t sae_reg_total_window;
    uint16_t sae_reg_min_window;
    uint16_t sae_reg_max_window;
    uint32_t sae_reg_var_window;

    uint16_t sae_reg_total_l4_payload_size;
    uint16_t sae_reg_min_l4_payload_size;
    uint16_t sae_reg_max_l4_payload_size;
    uint16_t sae_reg_mean_l4_payload_size;
    uint16_t sae_reg_var_l4_payload_size;

    uint8_t sae_reg_total_is_rst_flag;
    uint8_t sae_reg_total_is_psh_flag;
    uint8_t sae_reg_total_is_keep_alive;
    uint8_t sae_reg_total_is_sync_flood;
};

namespace p4rt {
namespace cia {
namespace appClassification {

// P4Runtime client details
class P4RuntimeClient {
public:
    P4RuntimeClient(const std::string& address);
    void WriteRequest(const p4::v1::WriteRequest& request);
    void SetForwardingPipelineConfig(const p4::v1::ForwardingPipelineConfig& config);
private:
    std::unique_ptr<p4::v1::P4Runtime::Stub> stub_;
};

// Function prototypes
void ipv4_host_table_send_action_add(P4RuntimeClient& client, uint32_t addr, uint16_t port);
p4::config::v1::P4Info setUp(std::string );
void tableSetUp(const p4::config::v1::P4Info &p4info);
void mirror_table_cpu_entry(P4RuntimeClient& client);

}  // namespace appClassification
}  // namespace cia
}  // namespace p4rt

void parse_options(int argc, char **argv);
int listening_cpu_port();
void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

