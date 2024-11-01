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
#include <thread>
#include <chrono>
#include <iomanip> 

#include "p4/config/v1/p4info.pb.h"
#include <grpcpp/grpcpp.h>
#include "p4/v1/p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"

#define FORWARD_TABLE_ID 37882547
#define MATCH_FIELD_ID 37882548
#define ACTION_ID 32848556
std::string ip_address = "\xC0\xA8\x01\x01";  // 192.168.1.1

#ifndef _IPC_H_
#define _IPC_H_
#include "../ipc/IPC.hpp"
#endif

#ifndef _P4RT_HPP_
#define _P4RT_HPP_
#include "p4rt.hpp"
#endif

namespace p4rt {
namespace cia {
namespace appClassification {

// P4 Runtime client stub
std::unique_ptr<p4::v1::P4Runtime::Stub> p4runtime_stub;

void close_process_handler(int signum);
void parse_options(int argc, char **argv);

std::shared_ptr<grpc::Channel> channel;
std::unique_ptr<p4::v1::P4Runtime::Stub> stub;

int getTableId(const std::string &table_name, const p4::config::v1::P4Info &p4info) {
    for (const auto &table : p4info.tables()) {
        // std::cout << table.preamble().name() <<std::endl;
        if (table.preamble().name() == table_name) {
            return table.preamble().id();
        }
    }
    throw std::runtime_error("Table not found: " + table_name);
}

int getRegisterId(const std::string &register_name, const p4::config::v1::P4Info &p4info) {
    for (const auto &registers : p4info.registers()) {
        if (registers.preamble().name() == register_name) {
            // std::cout << registers.type_spec().bitstring().ByteSizeLong()<<std::endl;
            return registers.preamble().id();
        }
        // std::cout<< registers.preamble().name() << std::endl;
    }
    throw std::runtime_error("Action not found: " + register_name);
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
                const p4::config::v1::Action* action_now = nullptr;
                for (const auto& act : p4info.actions()) {
                    if (act.preamble().id() == action.id()) {
                        action_now = &act;
                        break;
                    }
                }
                for (const auto &param :action_now->params()) {
                    if (param.name() == field_name) {
                        return param.id();
                    }
                }
            }
        }
    }
    throw std::runtime_error("Field not found: " + field_name);
}
void registerIdSet(std::string register_name, int index, int value, p4::config::v1::P4Info p4info);
void setMirror(const p4::config::v1::P4Info &p4info, int session_id, int egress_port, int length_bytes) {
    // 設置 $mirror.cfg 表項
    p4::v1::WriteRequest write_request;
    write_request.set_device_id(1);
    p4::v1::Uint128 *election_id = p4::v1::Uint128().New();
    election_id->set_high(0);
    election_id->set_low(1);

    write_request.set_allocated_election_id(election_id);
    
    p4::v1::Update* updates = write_request.add_updates();
    updates->set_type(p4::v1::Update_Type_INSERT); 
    p4::v1::Entity *entity = new p4::v1::Entity();
    p4::v1::PacketReplicationEngineEntry *rep = new p4::v1::PacketReplicationEngineEntry();
    p4::v1::CloneSessionEntry* clone = new p4::v1::CloneSessionEntry();
    clone->set_session_id(session_id);
    // clone->set_class_of_service(2);
    clone->set_packet_length_bytes(length_bytes);
    p4::v1::Replica* replica = clone->add_replicas();
    replica->set_egress_port(egress_port);
    replica->set_instance(0);
    

    rep->set_allocated_clone_session_entry(clone);
    entity->set_allocated_packet_replication_engine_entry(rep);
    updates->set_allocated_entity(entity);
    p4::v1::WriteResponse write_response;

    grpc::ClientContext *context = new grpc::ClientContext();
    grpc::Status status = p4runtime_stub->Write(context, write_request, &write_response);
    
    // std::cout<< write_request.DebugString() << std::endl; // This should use cout instead of printf
    if (!status.ok()) {
        std::cerr << "Error inserting table entry: " << status.error_message() << std::endl;
        std::cerr << "Error details: " << status.error_details() << std::endl;
    }
}

void setTableEntry(const p4::config::v1::P4Info &p4info, const std::string &table_name,
                   const std::string &action_name, const std::vector<std::pair<std::string, std::string>> &matches,
                   const std::vector<std::pair<std::string, std::string>> &params) {
    int table_id = getTableId(table_name, p4info);
    int action_id = getActionId(action_name, p4info);
    // std::cout << table_id<<" "<<action_id <<std::endl;
    p4::v1::TableEntry *table_entry = new p4::v1::TableEntry();
    table_entry->set_table_id(table_id);

    for (const auto &match : matches) {
        auto match_field = table_entry->add_match();
        // std::cout << getFieldId(match.first, p4info, true) <<std::endl;
        match_field->set_field_id(getFieldId(match.first, p4info, true));
        auto exact = match_field->mutable_exact();
        exact->set_value(match.second);
    }

    // auto action = table_entry.mutable_action()->mutable_action();
    p4::v1::Action *action = new p4::v1::Action();
    action->set_action_id(action_id);

    for (const auto &param : params) {
        auto param_field = action->add_params();
        param_field->set_param_id(getFieldId(param.first, p4info, false));
        param_field->set_value(param.second);
    }

    p4::v1::WriteRequest write_request;
    write_request.set_device_id(1);
    p4::v1::Uint128 *election_id = p4::v1::Uint128().New();
    election_id->set_high(0);
    election_id->set_low(1);

    write_request.set_allocated_election_id(election_id);
    
    p4::v1::Update* updates = write_request.add_updates();
    updates->set_type(p4::v1::Update_Type_INSERT); // Set the update type
    
    p4::v1::TableAction *table_action = new p4::v1::TableAction();
    p4::v1::Entity *entity = new p4::v1::Entity();
    table_action->set_allocated_action(action);
    table_entry->set_allocated_action(table_action);

    entity->set_allocated_table_entry(table_entry);
    updates->set_allocated_entity(entity);
    // updates->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

    grpc::ClientContext context;
    p4::v1::WriteResponse write_response;


    auto status = p4runtime_stub->Write(&context, write_request, &write_response);

    if (!status.ok()) {
        std::cerr << "Error inserting table entry: " << status.error_message() << std::endl;
    }
}

void tableSetUp(const p4::config::v1::P4Info &p4info) {
    std::vector<std::pair<std::string, std::string>> matches;
    std::vector<std::pair<std::string, std::string>> params;

    // 設置 Ingress_1.ipv4_host 表項
    matches = {{"hdr.ipv4.dst_addr", "\x0A\x01\x01\x0A"}};
    params = {{"port", "\x01"}};
    setTableEntry(p4info, "Ingress_1.ipv4_host", "Ingress_1.send", matches, params);

    // 設置 Ingress_2.ipv4_host 表項
    matches = {{"hdr.ipv4.dst_addr", "\x0A\x01\x01\x0A"}};
    params = {{"port", "\x00\x02"}};
    setTableEntry(p4info, "Ingress_2.ipv4_host", "Ingress_2.send", matches, params);

    setMirror(p4info, 5, 64, 136);
    setMirror(p4info, 6, 316, 136);
    
}

p4::config::v1::P4Info setUp(std::string channel_name) {
    // Initialize gRPC client
    auto channel = grpc::CreateChannel(channel_name, grpc::InsecureChannelCredentials());
    p4runtime_stub = p4::v1::P4Runtime::NewStub(channel);

    // // Create and set up a P4Runtime WriteRequest
    // p4::v1::WriteRequest write_request;
    // write_request.set_device_id(1);  // Example device ID

    // // Set the role_id to 0 for default role
    // write_request.set_role_id(0);

    // Create a bidirectional stream for arbitration
    grpc::ClientContext stream_context;
    std::shared_ptr<grpc::ClientReaderWriter<p4::v1::StreamMessageRequest, p4::v1::StreamMessageResponse>> stream(
        p4runtime_stub->StreamChannel(&stream_context));

    // Send MasterArbitrationUpdate to become the master controller
    p4::v1::StreamMessageRequest arbitration_request;
    p4::v1::MasterArbitrationUpdate* arbitration_update = arbitration_request.mutable_arbitration();
    arbitration_update->set_device_id(1);

    p4::v1::Uint128* election_id = arbitration_update->mutable_election_id();
    election_id->set_high(0);
    election_id->set_low(1);

    if (!stream->Write(arbitration_request)) {
        std::cerr << "Failed to send MasterArbitrationUpdate" << std::endl;
    }

    // Wait for arbitration response
    p4::v1::StreamMessageResponse arbitration_response;
    if (!stream->Read(&arbitration_response)) {
        std::cerr << "Failed to receive MasterArbitrationUpdate response" << std::endl;
    }

    if (arbitration_response.has_arbitration() && arbitration_response.arbitration().status().code() != grpc::StatusCode::OK) {
        std::cerr << "Master arbitration failed: " << arbitration_response.arbitration().status().message() << std::endl;
    }

    
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
        p4rt::cia::appClassification::tableSetUp(p4info);
        return p4info;
    }
    exit(0);
}

void setUpRegister(std::string channel_name, int fwd_id, int bwd_id) {
    // Initialize gRPC client
    auto channel = grpc::CreateChannel(channel_name, grpc::InsecureChannelCredentials());
    p4runtime_stub = p4::v1::P4Runtime::NewStub(channel);

    // Create a bidirectional stream for arbitration
    grpc::ClientContext stream_context;
    std::shared_ptr<grpc::ClientReaderWriter<p4::v1::StreamMessageRequest, p4::v1::StreamMessageResponse>> stream(
        p4runtime_stub->StreamChannel(&stream_context));

    // Send MasterArbitrationUpdate to become the master controller
    p4::v1::StreamMessageRequest arbitration_request;
    p4::v1::MasterArbitrationUpdate* arbitration_update = arbitration_request.mutable_arbitration();
    arbitration_update->set_device_id(1);

    p4::v1::Uint128* election_id = arbitration_update->mutable_election_id();
    election_id->set_high(0);
    election_id->set_low(1);

    if (!stream->Write(arbitration_request)) {
        std::cerr << "Failed to send MasterArbitrationUpdate" << std::endl;
    }

    // Wait for arbitration response
    p4::v1::StreamMessageResponse arbitration_response;
    if (!stream->Read(&arbitration_response)) {
        std::cerr << "Failed to receive MasterArbitrationUpdate response" << std::endl;
    }

    if (arbitration_response.has_arbitration() && arbitration_response.arbitration().status().code() != grpc::StatusCode::OK) {
        std::cerr << "Master arbitration failed: " << arbitration_response.arbitration().status().message() << std::endl;
    }

    
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
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_cur_index", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_rev_cur_index", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_reg_pkt_count", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_pkt_size", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_total_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_total_pkt_size", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_min_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_min_pkt_size", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_max_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_max_pkt_size", bwd_id, 0, p4info);
        // p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_var_pkt_size", fwd_id, 0, p4info);
        // p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_var_pkt_size", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_ttl", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_ttl", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_total_ttl", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_total_ttl", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_min_ttl", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_min_ttl", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_fwd_max_ttl", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_1.hash_mapping_tv_reg_bwd_max_ttl", bwd_id, 0, p4info);
        // p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_cur_index", fwd_id, 0, p4info);
        // p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_rev_cur_index", bwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_reg_pkt_count", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_total_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_min_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_prev_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_var_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_first_pkt_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_total_window", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_min_window", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_max_window", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_prev_window", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_var_window", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_first_window", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_total_l4_payload_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_min_l4_payload_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_max_l4_payload_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_prev_l4_payload_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_var_l4_payload_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_first_l4_payload_size", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_total_is_rst_flag", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_total_is_psh_flag", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_total_is_keep_alive", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_tv_reg_prev_fwd_syn_flag", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_total_is_sync_flood", fwd_id, 0, p4info);
        p4rt::cia::appClassification::registerIdSet("Egress_2.hash_mapping_sae_reg_irtt_tstamp", fwd_id, 0, p4info);
    }
}

void registerIdSet(std::string register_name, int index_id, int value, p4::config::v1::P4Info p4info) {
    int register_id = p4rt::cia::appClassification::getRegisterId(register_name, p4info);

    p4::v1::WriteRequest write_request;
    write_request.set_device_id(1);
    p4::v1::Uint128 *election_id = p4::v1::Uint128().New();
    election_id->set_high(0);
    election_id->set_low(1);

    write_request.set_allocated_election_id(election_id);
    
    auto* update = write_request.add_updates();
    // update->set_type(p4::v1::Update_Type_UNSPECIFIED);
    update->set_type(p4::v1::Update_Type_MODIFY);

    auto* entity = update->mutable_entity();
    auto* register_entry = entity->mutable_register_entry();
    register_entry->set_register_id(register_id);

    auto* index = register_entry->mutable_index();
    index->set_index(index_id);
    const char bit = static_cast<const char>(value);
    register_entry->mutable_data()->set_bitstring(&bit);

    grpc::ClientContext context;
    p4::v1::WriteResponse response;
    
    auto status = p4runtime_stub->Write(&context, write_request, &response);

    if (!status.ok()) {
        std::cerr << "P4 Runtime Write failed: " << status.error_message() << std::endl;
    }
}

// void ipv4_host_table_send_action_add(uint32_t addr, uint16_t port) {
//     p4::v1::WriteRequest write_request;
//     write_request.set_device_id(1); // Device ID

//     auto* update = write_request.add_updates();
//     update->set_type(p4::v1::Update_Type_INSERT);

//     auto* entity = update->mutable_entity();
//     auto* table_entry = entity->mutable_table_entry();
//     table_entry->set_table_id(FORWARD_TABLE_ID);

//     // Match key setup
//     auto* match = table_entry->add_match();
//     match->set_field_id(MATCH_FIELD_ID);
//     match->mutable_exact()->set_value(ip_address);

//     // Action setup
//     auto* action = table_entry->mutable_action()->mutable_action();
//     action->set_action_id(ACTION_ID);

//     // Action parameters
//     auto* param = action->add_params();
//     param->set_param_id(12345);
//     uint16_t port_number = 8080;
//     std::string port_number_bytes = std::string(reinterpret_cast<const char*>(&port_number), sizeof(port_number));
//     param->set_value(port_number_bytes);

//     grpc::ClientContext context;
//     p4::v1::WriteResponse response;
//     auto status = p4runtime_stub->Write(&context, write_request, &response);

//     if (!status.ok()) {
//         std::cerr << "P4 Runtime Write failed: " << status.error_message() << std::endl;
//     }
// }

// int mirror_table_id_1, mirror_table_id_2;
// int mirror_action_id_1, mirror_action_id_2;
// int mirror_sid_field_id_1, mirror_sid_field_id_2;
// int mirror_direction_field_id_1, mirror_direction_field_id_2;
// int mirror_session_enable_field_id_1, mirror_session_enable_field_id_2;
// int mirror_ucast_egress_port_field_id_1, mirror_ucast_egress_port_field_id_2;
// int mirror_ucast_egress_port_valid_field_id_1, mirror_ucast_egress_port_valid_field_id_2;
// int mirror_egress_port_queue_field_id_1, mirror_egress_port_queue_field_id_2;
// int mirror_max_pkt_len_field_id_1, mirror_max_pkt_len_field_id_2;

// void initializeIds(const p4::config::v1::P4Info &p4info) {
//     mirror_table_id_1 = getTableId("$mirror.cfg", p4info);
//     mirror_table_id_2 = getTableId("$mirror.cfg", p4info);

//     mirror_action_id_1 = getActionId("$normal", p4info);
//     mirror_action_id_2 = getActionId("$normal", p4info);

//     mirror_sid_field_id_1 = getFieldId("$sid", p4info, true);
//     mirror_sid_field_id_2 = getFieldId("$sid", p4info, true);

//     mirror_direction_field_id_1 = getFieldId("$direction", p4info, false);
//     mirror_direction_field_id_2 = getFieldId("$direction", p4info, false);

//     mirror_session_enable_field_id_1 = getFieldId("$session_enable", p4info, false);
//     mirror_session_enable_field_id_2 = getFieldId("$session_enable", p4info, false);

//     mirror_ucast_egress_port_field_id_1 = getFieldId("$ucast_egress_port", p4info, false);
//     mirror_ucast_egress_port_field_id_2 = getFieldId("$ucast_egress_port", p4info, false);

//     mirror_ucast_egress_port_valid_field_id_1 = getFieldId("$ucast_egress_port_valid", p4info, false);
//     mirror_ucast_egress_port_valid_field_id_2 = getFieldId("$ucast_egress_port_valid", p4info, false);

//     mirror_egress_port_queue_field_id_1 = getFieldId("$egress_port_queue", p4info, false);
//     mirror_egress_port_queue_field_id_2 = getFieldId("$egress_port_queue", p4info, false);

//     mirror_max_pkt_len_field_id_1 = getFieldId("$max_pkt_len", p4info, false);
//     mirror_max_pkt_len_field_id_2 = getFieldId("$max_pkt_len", p4info, false);
// }

// void setMirrorTableEntry(uint32_t sid, uint64_t port, int mirror_table_id, int mirror_action_id,
//                          int mirror_sid_field_id, int mirror_direction_field_id, int mirror_session_enable_field_id,
//                          int mirror_ucast_egress_port_field_id, int mirror_ucast_egress_port_valid_field_id,
//                          int mirror_egress_port_queue_field_id, int mirror_max_pkt_len_field_id) {
//     p4::v1::TableEntry table_entry;
//     table_entry.set_table_id(mirror_table_id);

//     // 設置鍵
//     auto match_field = table_entry.add_match();
//     match_field->set_field_id(mirror_sid_field_id);
//     auto exact = match_field->mutable_exact();
//     exact->set_value(std::string(reinterpret_cast<char*>(&sid), sizeof(sid)));

//     // 設置動作
//     auto action = table_entry.mutable_action()->mutable_action();
//     action->set_action_id(mirror_action_id);

//     // 設置數據字段
//     auto param = action->add_params();
//     param->set_param_id(mirror_direction_field_id);
//     param->set_value("BOTH");

//     param = action->add_params();
//     param->set_param_id(mirror_session_enable_field_id);
//     param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(bool)));

//     param = action->add_params();
//     param->set_param_id(mirror_ucast_egress_port_field_id);
//     param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(port)));

//     param = action->add_params();
//     param->set_param_id(mirror_ucast_egress_port_valid_field_id);
//     param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(bool)));

//     param = action->add_params();
//     param->set_param_id(mirror_egress_port_queue_field_id);
//     param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(port)));

//     param = action->add_params();
//     param->set_param_id(mirror_max_pkt_len_field_id);
//     param->set_value(std::string(reinterpret_cast<char*>(&port), sizeof(port)));

//     p4::v1::WriteRequest write_request;
//     write_request.set_device_id(1);
//     auto update = write_request.add_updates();
//     update->set_type(p4::v1::Update::INSERT);
//     update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

//     grpc::ClientContext context;
//     p4::v1::WriteResponse write_response;
//     auto status = p4runtime_stub->Write(&context, write_request, &write_response);
//     if (!status.ok()) {
//         std::cerr << "Error inserting table entry: " << status.error_message() << std::endl;
//     }
// }

// void mirror_table_cpu_entry() {
//     setMirrorTableEntry(mirror_sid_1, mirror_port_1, mirror_table_id_1, mirror_action_id_1,
//                         mirror_sid_field_id_1, mirror_direction_field_id_1, mirror_session_enable_field_id_1,
//                         mirror_ucast_egress_port_field_id_1, mirror_ucast_egress_port_valid_field_id_1,
//                         mirror_egress_port_queue_field_id_1, mirror_max_pkt_len_field_id_1);

//     setMirrorTableEntry(mirror_sid_2, mirror_port_2, mirror_table_id_2, mirror_action_id_2,
//                         mirror_sid_field_id_2, mirror_direction_field_id_2, mirror_session_enable_field_id_2,
//                         mirror_ucast_egress_port_field_id_2, mirror_ucast_egress_port_valid_field_id_2,
//                         mirror_egress_port_queue_field_id_2, mirror_max_pkt_len_field_id_2);
// }

// int ipv4_host_table_id_1, ipv4_host_table_id_2;
// int ipv4_host_action_id_1, ipv4_host_action_id_2;
// int ipv4_host_key_field_id_1, ipv4_host_key_field_id_2;
// int ipv4_host_port_field_id_1, ipv4_host_port_field_id_2;

// void initializeIpv4(const p4::config::v1::P4Info &p4info) {
//     ipv4_host_table_id_1 = getTableId("Ingress_1.ipv4_host", p4info);
//     ipv4_host_table_id_2 = getTableId("Ingress_2.ipv4_host", p4info);

//     ipv4_host_action_id_1 = getActionId("Ingress_1.send", p4info);
//     ipv4_host_action_id_2 = getActionId("Ingress_2.send", p4info);

//     ipv4_host_key_field_id_1 = getFieldId("hdr.ipv4.dst_addr", p4info, true);
//     ipv4_host_key_field_id_2 = getFieldId("hdr.ipv4.dst_addr", p4info, true);

//     ipv4_host_port_field_id_1 = getFieldId("port", p4info, false);
//     ipv4_host_port_field_id_2 = getFieldId("port", p4info, false);
// }

}  // namespace appClassification
}  // namespace cia
}  // namespace bfrt

// void parse_options(int argc, char **argv) {
//     int option_index = 0;
//     enum opts {
//         OPT_INSTALLDIR = 1,
//         OPT_CONFFILE,
//     };
//     static struct option options[] = {
//         {"help", no_argument, 0, 'h'},
//         {"install-dir", required_argument, 0, OPT_INSTALLDIR},
//         {"conf-file", required_argument, 0, OPT_CONFFILE}
//     };

//     std::string install_dir;
//     std::string conf_file;

//     while (1) {
//         int c = getopt_long(argc, argv, "h", options, &option_index);

//         if (c == -1) {
//             break;
//         }
//         switch (c) {
//             case OPT_INSTALLDIR:
//                 install_dir = optarg;
//                 std::cout << "Install Dir: " << install_dir << std::endl;
//                 break;
//             case OPT_CONFFILE:
//                 conf_file = optarg;
//                 std::cout << "Conf-file : " << conf_file << std::endl;
//                 break;
//             case 'h':
//             case '?':
//                 std::cout << "Usage: program --install-dir=path --conf-file=path" << std::endl;
//                 exit(c == 'h' ? 0 : 1);
//                 break;
//             default:
//                 std::cout << "Invalid option" << std::endl;
//                 exit(1);
//                 break;
//         }
//     }
//     if (install_dir.empty()) {
//         std::cerr << "ERROR: --install-dir must be specified" << std::endl;
//         exit(1);
//     }
//     if (conf_file.empty()) {
//         std::cerr << "ERROR: --conf-file must be specified" << std::endl;
//         exit(1);
//     }
// }

// void run_p4runtime_client() {
//     while (true) {
//         std::this_thread::sleep_for(std::chrono::seconds(1));
//     }
// }

// void send_packet_in(p4::v1::PacketIn packet_in) {
//     grpc::ClientContext context;
//     p4::v1::StreamMessageRequest request;
//     request.mutable_packet()->CopyFrom(packet_in);

//     std::shared_ptr<grpc::ClientReaderWriter<p4::v1::StreamMessageRequest, p4::v1::StreamMessageResponse>> stream(
//         p4rt::cia::appClassification::p4runtime_stub->StreamChannel(&context));

//     stream->Write(request);
//     stream->WritesDone();
//     grpc::Status status = stream->Finish();
//     if (!status.ok()) {
//         std::cerr << "Error sending PacketIn: " << status.error_message() << std::endl;
//     }
// }

//--------底下function照舊

std::unordered_map<int, std::vector<sniff_five_tuple_tv *>> flows;

int counter = 0;

void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // std::cout << counter++ << " Pkt Recv" << std::endl;
    
    clock_t startTime, endTime;
    startTime = clock();
    
    u_char byte_array[48] = {0};
    for (size_t i = 0; i < 48; ++i) {
        byte_array[i] = packet[i+14];
    }
    // for (size_t i = 0; i < 48; ++i) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_array[i]) << " ";
    //     if ((i + 1) % 16 == 0) {
    //         std::cout <<std::dec << std::endl;
    //     }
    // }
    // std::cout <<std::dec << std::endl;
    // printPacket(packet, length);

    const sniff_five_tuple_tv* f_tuple_tv = reinterpret_cast<const sniff_five_tuple_tv*>(packet + SIZE_ETHERNET);
    sniff_five_tuple_tv *f_tuple_tv_new = new sniff_five_tuple_tv;
    sniff_five_tuple_ss *f_tuple_ss = (sniff_five_tuple_ss*)(packet + SIZE_ETHERNET);

    // f_tuple_tv = reinterpret_cast<sniff_five_tuple_tv*>(packet + SIZE_ETHERNET);
    // f_tuple_ss = reinterpret_cast<sniff_five_tuple_ss*>(packet + SIZE_ETHERNET);

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
        // std::cout << (int)ntohs(f_tuple_ss->session_id) << std::endl;
        // std::cout << (flows.find((int)ntohs(f_tuple_ss->session_id)) != flows.end()) << std::endl;

        if (flows.find((int)ntohs(f_tuple_ss->session_id)) != flows.end() && flows[(int)ntohs(f_tuple_ss->session_id)].size() == 8) {
            for (auto tv_pkt : flows[(int)ntohs(f_tuple_ss->session_id)]) {
                std::cout << "session_id: " << ntohs(tv_pkt->session_id) << std::endl;
                std::cout << "pkt_count: " << ntohs(tv_pkt->reg_pkt_count) << std::endl;

                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_total_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_total_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_var_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_var_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_min_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_min_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_max_pkt_size)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_max_pkt_size)));


                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_total_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_total_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_var_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_var_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_min_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_min_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_fwd_max_iat)) * pow(10, -6));
                // cnn1DInput.push_back(float(ntohl(tv_pkt->tv_reg_bwd_max_iat)) * pow(10, -6));

                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_total_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_total_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_var_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_var_ttl)));
                // cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_min_ttl)));
                // cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_min_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_fwd_max_ttl)));
                cnn1DInput.push_back(float(ntohs(tv_pkt->tv_reg_bwd_max_ttl)));

            }

            std::cout << "ss_session_id: " << ntohs(f_tuple_ss->session_id) << std::endl;
            std::cout << "ss_fwd_id: " << ntohs(f_tuple_ss->fwd_id) << std::endl;
            std::cout << "ss_bwd_id: " << ntohs(f_tuple_ss->bwd_id) << std::endl;
            std::cout.flush();

            f_tuple_ss->sae_reg_service_type = uint32_t(byte_array[12]<<8|byte_array[13]);
            f_tuple_ss->sae_reg_total_pkt_size = uint32_t(byte_array[14]<<8|byte_array[15]);
            f_tuple_ss->sae_reg_min_pkt_size = uint32_t(byte_array[16]<<8|byte_array[17]);
            f_tuple_ss->sae_reg_mean_pkt_size = uint32_t(byte_array[18]<<8|byte_array[19]);
            f_tuple_ss->sae_reg_var_pkt_size = uint32_t(byte_array[20]<<8|byte_array[21]);
            f_tuple_ss->sae_reg_total_window = uint32_t(byte_array[22]<<24|byte_array[23]<<16|byte_array[24]<<8|byte_array[25]);
            f_tuple_ss->sae_reg_min_window = uint32_t(byte_array[26]<<8|byte_array[27]);
            f_tuple_ss->sae_reg_max_window = uint32_t(byte_array[28]<<8|byte_array[29]);
            f_tuple_ss->sae_reg_var_window = uint32_t(byte_array[30]<<24|byte_array[31]<<16|byte_array[32]<<8|byte_array[33]);
            f_tuple_ss->sae_reg_total_l4_payload_size = uint32_t(byte_array[34]<<8|byte_array[35]);
            f_tuple_ss->sae_reg_min_l4_payload_size = uint32_t(byte_array[36]<<8|byte_array[37]);
            f_tuple_ss->sae_reg_max_l4_payload_size = uint32_t(byte_array[38]<<8|byte_array[39]);
            f_tuple_ss->sae_reg_mean_l4_payload_size = uint32_t(byte_array[40]<<8|byte_array[41]);
            f_tuple_ss->sae_reg_var_l4_payload_size = uint32_t(byte_array[42]<<8|byte_array[43]);
            f_tuple_ss->sae_reg_total_is_rst_flag = uint32_t(byte_array[44]);
            f_tuple_ss->sae_reg_total_is_psh_flag = uint32_t(byte_array[45]);
            f_tuple_ss->sae_reg_total_is_keep_alive = uint32_t(byte_array[46]);
            f_tuple_ss->sae_reg_total_is_sync_flood = uint32_t(byte_array[47]);

            // std::cout << f_tuple_ss->sae_reg_total_window <<std::endl;
            // std::cout << ntohl(f_tuple_ss->sae_reg_total_window)<<std::endl;
            saeInput.push_back(float(f_tuple_ss->sae_reg_total_pkt_size));
            saeInput.push_back(float(f_tuple_ss->sae_reg_mean_pkt_size));
            saeInput.push_back(float(f_tuple_ss->sae_reg_var_pkt_size));
            saeInput.push_back(float(f_tuple_ss->sae_reg_min_pkt_size));
            // saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_total_iat)) * pow(10, -6));
            // saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_mean_iat)) * pow(10, -6));
            // saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_min_iat)) * pow(10, -6));
            // saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_max_iat)) * pow(10, -6));
            // saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_session_connection_time)) * pow(10, -6));
            saeInput.push_back(float(f_tuple_ss->sae_reg_service_type));
            // saeInput.push_back(float(ntohl(f_tuple_ss->sae_reg_irtt)) * pow(10, 3));
            saeInput.push_back(float(f_tuple_ss->sae_reg_total_window));
            // saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_mean_window)));
            // std::cout << f_tuple_ss->sae_reg_var_window <<std::endl;
            saeInput.push_back(float(f_tuple_ss->sae_reg_var_window/8));
            saeInput.push_back(float(f_tuple_ss->sae_reg_min_window));
            saeInput.push_back(float(f_tuple_ss->sae_reg_max_window));
            // saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_total_l4_payload_size)));
            // saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_mean_l4_payload_size)));
            // saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_var_l4_payload_size)));
            // saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_min_l4_payload_size)));
            // saeInput.push_back(float(ntohs(f_tuple_ss->sae_reg_max_l4_payload_size)));
            saeInput.push_back(float(f_tuple_ss->sae_reg_total_is_rst_flag));
            saeInput.push_back(float(f_tuple_ss->sae_reg_total_is_psh_flag));
            saeInput.push_back(float(f_tuple_ss->sae_reg_total_is_keep_alive));
            saeInput.push_back(float(f_tuple_ss->sae_reg_total_is_sync_flood));
            IPC::writeToIPC(cnn1DInput, saeInput);

            endTime = clock();
            std::cout << "Time = " << double(endTime - startTime) / CLOCKS_PER_SEC << "s" << std::endl;
            std::string *channel_name = (std::string *)userData;
            // p4rt::cia::appClassification::setUpRegister(*channel_name, ntohs(f_tuple_ss->fwd_id), ntohs(f_tuple_ss->bwd_id));
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

int listening_cpu_port(std::string channel_name) {
    std::string dev = "enp4s0f1";
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    // p4rt::cia::appClassification::getRegisterId("", p4info);
    descr = pcap_open_live(dev.c_str(), mirror_max_pkt_len, 1, -1, errbuf);  // 65535最大，表示不切割封包
    if (descr == NULL) {
        std::cout << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    if (pcap_loop(descr, -1, packet_handler, (u_char *)&channel_name) < 0) {
        std::cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    return 0;
}

void close_process_handler(int signum) {
    std::cout << "Caught signal " << signum << std::endl;
    std::cout << "close program" << std::endl;

    system("bfshell -f /root/cia/samuel/p4-AppClassification/initial_config/close_port_configuration.txt");
    sleep(2);
    exit(signum);
}

int main(int argc, char **argv) {
    signal(SIGINT, close_process_handler);

    std::cout << "--------- Run P4 configuration ---------" << std::endl;

    // Set up P4Runtime using the new function
    p4::config::v1::P4Info p4info = p4rt::cia::appClassification::setUp(std::string(argv[1]));

    std::cout << "========= P4 configuration end =========" << std::endl;
   // Start listening on CPU port

    std::cerr << "--------- start to listening cpu port ---------" << std::endl;
    listening_cpu_port(std::string(argv[1]));

    return 0;
}



void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);