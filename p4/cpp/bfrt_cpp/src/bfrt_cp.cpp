#include <arpa/inet.h>
#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>

#include <array>
#include <cmath>
#include <ctime>
#include <iostream>
#include <unordered_map>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"

namespace bfrt {
namespace cia {
namespace appClassification {

// P4 Runtime client stub
std::unique_ptr<p4::v1::P4Runtime::Stub> p4runtime_stub;

void setUp() {
    // Initialize gRPC client
    auto channel = grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials());
    p4runtime_stub = p4::v1::P4Runtime::NewStub(channel);

    // Create and set up a P4Runtime WriteRequest
    p4::v1::WriteRequest write_request;
    write_request.set_device_id(1);  // Example device ID

    // Set the role_id to 0 for default role
    write_request.set_role_id(0);

    // Example: getting the P4Info
    p4::v1::GetForwardingPipelineConfigRequest get_request;
    get_request.set_device_id(1);  // Example device ID
    get_request.set_response_type(p4::v1::GetForwardingPipelineConfigRequest::P4INFO_AND_COOKIE);

    p4::v1::GetForwardingPipelineConfigResponse get_response;
    grpc::ClientContext context;
    auto status = p4runtime_stub->GetForwardingPipelineConfig(&context, get_request, &get_response);

    if (!status.ok()) {
        std::cerr << "P4Runtime GetForwardingPipelineConfig failed: " << status.error_message() << std::endl;
    } else {
        // Process the P4Info
        const p4::config::v1::P4Info& p4info = get_response.config().p4info();
        std::cout << "P4Info retrieved successfully." << std::endl;
    }
}

int getTableId(const std::string &table_name, const p4::config::v1::P4Info &p4info) {
    for (const auto &table : p4info.tables()) {
        if (table.preamble().name() == table_name) {
            return table.preamble().id();
        }
    }
    throw std::runtime_error("Table not found: " + table_name);
}

int getActionId(const std::string &action_name, const p4::config::v1::P4Info &p4info) {
    for (const auto &action : p4info.actions()) {
        if (action.preamble().name() == action_name) {
            return action.preamble().id();
        }
    }
    throw std::runtime_error("Action not found: " + action_name);
}

int getFieldId(const std::string &field_name, const p4::config::v1::P4Info &p4info, bool is_match_field) {
    for (const auto &table : p4info.tables()) {
        for (const auto &field : table.match_fields()) {
            if (field.name() == field_name) {
                return field.id();
            }
        }
    }
    if (!is_match_field) {
        for (const auto &table : p4info.tables()) {
            for (const auto &action : table.action_refs()) {
                for (const auto &param : p4info.actions(action.id()).params()) {
                    if (param.name() == field_name) {
                        return param.id();
                    }
                }
            }
        }
    }
    throw std::runtime_error("Field not found: " + field_name);
}

void setTableEntry(const p4::config::v1::P4Info &p4info, const std::string &table_name,
                   const std::string &action_name, const std::vector<std::pair<std::string, std::string>> &matches,
                   const std::vector<std::pair<std::string, std::string>> &params) {
    int table_id = getTableId(table_name, p4info);
    int action_id = getActionId(action_name, p4info);

    p4::v1::TableEntry table_entry;
    table_entry.set_table_id(table_id);

    for (const auto &match : matches) {
        auto match_field = table_entry.add_match();
        match_field->set_field_id(getFieldId(match.first, p4info, true));
        auto exact = match_field->mutable_exact();
        exact->set_value(match.second);
    }

    auto action = table_entry.mutable_action()->mutable_action();
    action->set_action_id(action_id);

    for (const auto &param : params) {
        auto param_field = action->add_params();
        param_field->set_param_id(getFieldId(param.first, p4info, false));
        param_field->set_value(param.second);
    }

    p4::v1::WriteRequest write_request;
    write_request.set_device_id(0);
    auto update = write_request.add_updates();
    update->set_type(p4::v1::Update::INSERT);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

    grpc::ClientContext context;
    p4::v1::WriteResponse write_response;
    auto status = p4runtime_stub->Write(&context, write_request, &write_response);
    if (!status.ok()) {
        std::cerr << "Error inserting table entry: " << status.error_message() << std::endl;
    }
}

void tableSetUp() {
    std::vector<std::pair<std::string, std::string>> matches;
    std::vector<std::pair<std::string, std::string>> params;

    // 設置 Ingress_1.ipv4_host 表項
    matches = {{"hdr.ipv4.dst_addr", "\x0a\x00\x00\x01"}};
    params = {{"port", "\x00\x01"}};
    setTableEntry(p4info, "Ingress_1.ipv4_host", "Ingress_1.send", matches, params);

    // 設置 Ingress_2.ipv4_host 表項
    matches = {{"hdr.ipv4.dst_addr", "\x0a\x00\x00\x02"}};
    params = {{"port", "\x00\x02"}};
    setTableEntry(p4info, "Ingress_2.ipv4_host", "Ingress_2.send", matches, params);

    // 設置 $mirror.cfg 表項
    matches = {{"$sid", "\x01"}};
    params = {
        {"$direction", "\x00"},
        {"$session_enable", "\x01"},
        {"$ucast_egress_port", "\x00\x01"},
        {"$ucast_egress_port_valid", "\x01"},
        {"$egress_port_queue", "\x01"},
        {"$max_pkt_len", "\x64"}
    };
    setTableEntry(p4info, "$mirror.cfg", "$normal", matches, params);

    matches = {{"$sid", "\x02"}};
    setTableEntry(p4info, "$mirror.cfg", "$normal", matches, params);
}

void ipv4_host_table_send_action_add(uint32_t addr, uint16_t port) {
    p4::v1::WriteRequest write_request;
    write_request.set_device_id(1); // Device ID

    auto* update = write_request.add_updates();
    update->set_type(p4::v1::Update_Type_INSERT);

    auto* entity = update->mutable_entity();
    auto* table_entry = entity->mutable_table_entry();
    table_entry->set_table_id(/* Table ID */);

    // Match key setup
    auto* match = table_entry->add_match();
    match->set_field_id(/* Match field ID */);
    match->mutable_exact()->set_value(/* IP address byte data */);

    // Action setup
    auto* action = table_entry->mutable_action()->mutable_action();
    action->set_action_id(/* Action ID */);

    // Action parameters
    auto* param = action->add_params();
    param->set_param_id(/* Parameter ID */);
    param->set_value(/* Port number byte data */);

    grpc::ClientContext context;
    p4::v1::WriteResponse response;
    auto status = p4runtime_stub->Write(&context, write_request, &response);

    if (!status.ok()) {
        std::cerr << "P4 Runtime Write failed: " << status.error_message() << std::endl;
    }
}

int mirror_table_id_1, mirror_table_id_2;
int mirror_action_id_1, mirror_action_id_2;
int mirror_sid_field_id_1, mirror_sid_field_id_2;
int mirror_direction_field_id_1, mirror_direction_field_id_2;
int mirror_session_enable_field_id_1, mirror_session_enable_field_id_2;
int mirror_ucast_egress_port_field_id_1, mirror_ucast_egress_port_field_id_2;
int mirror_ucast_egress_port_valid_field_id_1, mirror_ucast_egress_port_valid_field_id_2;
int mirror_egress_port_queue_field_id_1, mirror_egress_port_queue_field_id_2;
int mirror_max_pkt_len_field_id_1, mirror_max_pkt_len_field_id_2;

void initializeIds() {
    mirror_table_id_1 = getTableId("$mirror.cfg", p4info);
    mirror_table_id_2 = getTableId("$mirror.cfg", p4info);

    mirror_action_id_1 = getActionId("$normal", p4info);
    mirror_action_id_2 = getActionId("$normal", p4info);

    mirror_sid_field_id_1 = getFieldId("$sid", p4info, true);
    mirror_sid_field_id_2 = getFieldId("$sid", p4info, true);

    mirror_direction_field_id_1 = getFieldId("$direction", p4info, false);
    mirror_direction_field_id_2 = getFieldId("$direction", p4info, false);

    mirror_session_enable_field_id_1 = getFieldId("$session_enable", p4info, false);
    mirror_session_enable_field_id_2 = getFieldId("$session_enable", p4info, false);

    mirror_ucast_egress_port_field_id_1 = getFieldId("$ucast_egress_port", p4info, false);
    mirror_ucast_egress_port_field_id_2 = getFieldId("$ucast_egress_port", p4info, false);

    mirror_ucast_egress_port_valid_field_id_1 = getFieldId("$ucast_egress_port_valid", p4info, false);
    mirror_ucast_egress_port_valid_field_id_2 = getFieldId("$ucast_egress_port_valid", p4info, false);

    mirror_egress_port_queue_field_id_1 = getFieldId("$egress_port_queue", p4info, false);
    mirror_egress_port_queue_field_id_2 = getFieldId("$egress_port_queue", p4info, false);

    mirror_max_pkt_len_field_id_1 = getFieldId("$max_pkt_len", p4info, false);
    mirror_max_pkt_len_field_id_2 = getFieldId("$max_pkt_len", p4info, false);
}

void setMirrorTableEntry(uint32_t sid, uint64_t port, int mirror_table_id, int mirror_action_id,
                         int mirror_sid_field_id, int mirror_direction_field_id, int mirror_session_enable_field_id,
                         int mirror_ucast_egress_port_field_id, int mirror_ucast_egress_port_valid_field_id,
                         int mirror_egress_port_queue_field_id, int mirror_max_pkt_len_field_id) {
    p4::v1::TableEntry table_entry;
    table_entry.set_table_id(mirror_table_id);

    // 設置鍵
    auto match_field = table_entry.add_match();
    match_field->set_field_id(mirror_sid_field_id);
    auto exact = match_field->mutable_exact();
    exact->set_value(std::string(reinterpret_cast<char*>(&sid), sizeof(sid)));

    // 設置動作
    auto action = table_entry.mutable_action()->mutable_action();
    action->set_action_id(mirror_action_id);

    // 設置數據字段
    auto param = action->add_params();
    param->set_param_id(mirror_direction_field_id);
    param->set_value("BOTH");

    param = action->add_params();
    param->set_param_id(mirror_session_enable_field_id);
    param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(bool)));

    param = action->add_params();
    param->set_param_id(mirror_ucast_egress_port_field_id);
    param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(port)));

    param = action->add_params();
    param->set_param_id(mirror_ucast_egress_port_valid_field_id);
    param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(bool)));

    param = action->add_params();
    param->set_param_id(mirror_egress_port_queue_field_id);
    param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(port)));

    param = action->add_params();
    param->set_param_id(mirror_max_pkt_len_field_id);
    param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(port)));

    p4::v1::WriteRequest write_request;
    write_request.set_device_id(0);
    auto update = write_request.add_updates();
    update->set_type(p4::v1::Update::INSERT);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

    grpc::ClientContext context;
    p4::v1::WriteResponse write_response;
    auto status = p4runtime_stub->Write(&context, write_request, &write_response);
    if (!status.ok()) {
        std::cerr << "Error inserting table entry: " << status.error_message() << std::endl;
    }
}

void mirror_table_cpu_entry() {
    setMirrorTableEntry(mirror_sid_1, mirror_port_1, mirror_table_id_1, mirror_action_id_1,
                        mirror_sid_field_id_1, mirror_direction_field_id_1, mirror_session_enable_field_id_1,
                        mirror_ucast_egress_port_field_id_1, mirror_ucast_egress_port_valid_field_id_1,
                        mirror_egress_port_queue_field_id_1, mirror_max_pkt_len_field_id_1);

    setMirrorTableEntry(mirror_sid_2, mirror_port_2, mirror_table_id_2, mirror_action_id_2,
                        mirror_sid_field_id_2, mirror_direction_field_id_2, mirror_session_enable_field_id_2,
                        mirror_ucast_egress_port_field_id_2, mirror_ucast_egress_port_valid_field_id_2,
                        mirror_egress_port_queue_field_id_2, mirror_max_pkt_len_field_id_2);
}

int ipv4_host_table_id_1, ipv4_host_table_id_2;
int ipv4_host_action_id_1, ipv4_host_action_id_2;
int ipv4_host_key_field_id_1, ipv4_host_key_field_id_2;
int ipv4_host_port_field_id_1, ipv4_host_port_field_id_2;

void initializeIpv4() {
    ipv4_host_table_id_1 = getTableId("Ingress_1.ipv4_host", p4info);
    ipv4_host_table_id_2 = getTableId("Ingress_2.ipv4_host", p4info);

    ipv4_host_action_id_1 = getActionId("Ingress_1.send", p4info);
    ipv4_host_action_id_2 = getActionId("Ingress_2.send", p4info);

    ipv4_host_key_field_id_1 = getFieldId("hdr.ipv4.dst_addr", p4info, true);
    ipv4_host_key_field_id_2 = getFieldId("hdr.ipv4.dst_addr", p4info, true);

    ipv4_host_port_field_id_1 = getFieldId("port", p4info, false);
    ipv4_host_port_field_id_2 = getFieldId("port", p4info, false);
}

void setIpv4HostTableEntry(uint32_t addr, uint16_t port, int table_id, int action_id,
                           int key_field_id, int port_field_id) {
    p4::v1::TableEntry table_entry;
    table_entry.set_table_id(table_id);

    // 設置鍵
    auto match_field = table_entry.add_match();
    match_field->set_field_id(key_field_id);
    auto exact = match_field->mutable_exact();
    exact->set_value(std::string(reinterpret_cast<char*>(&addr), sizeof(addr)));

    // 設置動作
    auto action = table_entry.mutable_action()->mutable_action();
    action->set_action_id(action_id);

    // 設置數據字段
    auto param = action->add_params();
    param->set_param_id(port_field_id);
    param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(port)));

    p4::v1::WriteRequest write_request;
    write_request.set_device_id(0);
    auto update = write_request.add_updates();
    update->set_type(p4::v1::Update::INSERT);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

    grpc::ClientContext context;
    p4::v1::WriteResponse write_response;
    auto status = p4runtime_stub->Write(&context, write_request, &write_response);
    if (!status.ok()) {
        std::cerr << "Error inserting table entry: " << status.error_message() << std::endl;
    }
}

void ipv4_host_table_send_action_add(uint32_t addr, uint16_t port) {
    setIpv4HostTableEntry(addr, port, ipv4_host_table_id_1, ipv4_host_action_id_1,
                          ipv4_host_key_field_id_1, ipv4_host_port_field_id_1);

    setIpv4HostTableEntry(addr, port, ipv4_host_table_id_2, ipv4_host_action_id_2,
                          ipv4_host_key_field_id_2, ipv4_host_port_field_id_2);
}


}  // namespace appClassification
}  // namespace cia
}  // namespace bfrt

void parse_options(int argc, char **argv) {
    int option_index = 0;
    enum opts {
        OPT_INSTALLDIR = 1,
        OPT_CONFFILE,
    };
    static struct option options[] = {
        {"help", no_argument, 0, 'h'},
        {"install-dir", required_argument, 0, OPT_INSTALLDIR},
        {"conf-file", required_argument, 0, OPT_CONFFILE}
    };

    std::string install_dir;
    std::string conf_file;

    while (1) {
        int c = getopt_long(argc, argv, "h", options, &option_index);

        if (c == -1) {
            break;
        }
        switch (c) {
            case OPT_INSTALLDIR:
                install_dir = optarg;
                std::cout << "Install Dir: " << install_dir << std::endl;
                break;
            case OPT_CONFFILE:
                conf_file = optarg;
                std::cout << "Conf-file : " << conf_file << std::endl;
                break;
            case 'h':
            case '?':
                std::cout << "Usage: program --install-dir=path --conf-file=path" << std::endl;
                exit(c == 'h' ? 0 : 1);
                break;
            default:
                std::cout << "Invalid option" << std::endl;
                exit(1);
                break;
        }
    }
    if (install_dir.empty()) {
        std::cerr << "ERROR: --install-dir must be specified" << std::endl;
        exit(1);
    }
    if (conf_file.empty()) {
        std::cerr << "ERROR: --conf-file must be specified" << std::endl;
        exit(1);
    }
}

void run_p4runtime_client() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void send_packet_in(p4::v1::PacketIn packet_in) {
    grpc::ClientContext context;
    p4::v1::StreamMessageRequest request;
    request.mutable_packet()->CopyFrom(packet_in);

    std::shared_ptr<grpc::ClientReaderWriter<p4::v1::StreamMessageRequest, p4::v1::StreamMessageResponse>> stream(
        p4runtime_stub->StreamChannel(&context));

    stream->Write(request);
    stream->WritesDone();
    grpc::Status status = stream->Finish();
    if (!status.ok()) {
        std::cerr << "Error sending PacketIn: " << status.error_message() << std::endl;
    }
}

void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Initialize variables for start time measurement
    auto startTime = std::chrono::high_resolution_clock::now();

    sniff_five_tuple_tv *f_tuple_tv;
    sniff_five_tuple_tv *f_tuple_tv_new = new sniff_five_tuple_tv;
    sniff_five_tuple_ss *f_tuple_ss;

    f_tuple_tv = (struct sniff_five_tuple_tv *)(packet + SIZE_ETHERNET);
    f_tuple_ss = (struct sniff_five_tuple_ss *)(packet + SIZE_ETHERNET);

    memcpy(f_tuple_tv_new, f_tuple_tv, sizeof(sniff_five_tuple_tv));

    if (ntohs(f_tuple_tv->pkt_type) == TV_PACKET_TYPE) {
        std::cout << "type TV_PACKET_TYPE" << std::endl;

        p4::v1::PacketIn packet_in;
        packet_in.add_payload(packet, pkthdr->len);

        p4::v1::PacketMetadata *meta = packet_in.add_metadata();
        meta->set_metadata_id(TV_PACKET_TYPE); // Example metadata ID, replace with actual
        meta->set_value(packet, sizeof(sniff_five_tuple_tv)); // Example value, replace with actual

        send_packet_in(packet_in);

    } else if (ntohs(f_tuple_ss->pkt_type) == SS_PACKET_TYPE) {
        std::cout << "type SS_PACKET_TYPE" << std::endl;

        p4::v1::PacketIn packet_in;
        packet_in.add_payload(packet, pkthdr->len);

        p4::v1::PacketMetadata *meta = packet_in.add_metadata();
        meta->set_metadata_id(SS_PACKET_TYPE); // Example metadata ID, replace with actual
        meta->set_value(packet, sizeof(sniff_five_tuple_ss)); // Example value, replace with actual

        send_packet_in(packet_in);

        std::vector<float> cnn1DInput;
        std::vector<float> saeInput;

        if (flows.find((int)ntohs(f_tuple_ss->session_id)) != flows.end() && flows[(int)ntohs(f_tuple_ss->session_id)].size() == 8) {
            for (auto tv_pkt : flows[(int)ntohs(f_tuple_ss->session_id)]) {
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
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> time_span = endTime - startTime;
    std::cout << "Time = " << time_span.count() << "s" << std::endl;
}

void packet_handler(const p4::v1::PacketIn& packet_in) {
    const u_char* packet = reinterpret_cast<const u_char*>(packet_in.payload().data());
    struct pcap_pkthdr pkthdr;
    pkthdr.len = packet_in.payload().size();
    // Call the original packet handler function
    packet_handler(nullptr, &pkthdr, packet);
}

// Listen for PacketIn messages from P4Runtime
void listen_for_packets() {
    grpc::ClientContext context;
    auto stream = p4runtime_stub->StreamChannel(&context);

    // Send initial arbitration message
    p4::v1::StreamMessageRequest request;
    request.mutable_arbitration()->mutable_device_id()->set_device_id(1);
    stream->Write(request);

    p4::v1::StreamMessageResponse response;
    while (stream->Read(&response)) {
        if (response.update_case() == p4::v1::StreamMessageResponse::kPacket) {
            packet_handler(response.packet());
        }
    }

    grpc::Status status = stream->Finish();
    if (!status.ok()) {
        std::cerr << "StreamChannel failed: " << status.error_message() << std::endl;
    }
}

// Main function
int listening_cpu_port() {
    std::string p4runtime_server_address = "localhost:50051"; // Replace with actual address

    // Initialize P4Runtime client
    initialize_p4runtime(p4runtime_server_address);

    // Listen for packets
    listen_for_packets();

    return 0;
}

void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);