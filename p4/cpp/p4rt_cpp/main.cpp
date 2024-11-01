#include "p4/config/v1/p4info.pb.h"
#include "p4/v1/p4runtime.grpc.pb.h"
#include <grpc++/grpc++.h>
#include <stdio.h>
#include <iostream>

#define FORWARD_TABLE_ID 43211008
#define ACTION_ID 27928345

int main() {
    std::string server_address{"localhost:9559"};
    std::shared_ptr<grpc::Channel> chan;
    chan = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    std::unique_ptr<p4::v1::P4Runtime::Stub> service = p4::v1::P4Runtime::NewStub(chan);

    //-------
    // Create a bidirectional stream for arbitration
    grpc::ClientContext stream_context;
    std::shared_ptr<grpc::ClientReaderWriter<p4::v1::StreamMessageRequest, p4::v1::StreamMessageResponse>> stream(
        service->StreamChannel(&stream_context));

    // Send MasterArbitrationUpdate to become the master controller
    p4::v1::StreamMessageRequest arbitration_request;
    p4::v1::MasterArbitrationUpdate* arbitration_update = arbitration_request.mutable_arbitration();
    arbitration_update->set_device_id(1);
    p4::v1::Uint128* election_id = arbitration_update->mutable_election_id();
    election_id->set_high(0);
    election_id->set_low(1);

    if (!stream->Write(arbitration_request)) {
        std::cerr << "Failed to send MasterArbitrationUpdate" << std::endl;
        return 1;
    }

    // Wait for arbitration response
    p4::v1::StreamMessageResponse arbitration_response;
    if (!stream->Read(&arbitration_response)) {
        std::cerr << "Failed to receive MasterArbitrationUpdate response" << std::endl;
        return 1;
    }

    if (arbitration_response.has_arbitration() && arbitration_response.arbitration().status().code() != grpc::StatusCode::OK) {
        std::cerr << "Master arbitration failed: " << arbitration_response.arbitration().status().message() << std::endl;
        return 1;
    }
    //-------
    
    grpc::ClientContext *context = new grpc::ClientContext();
    p4::v1::GetForwardingPipelineConfigRequest get_pipe_cfg_req;
    p4::v1::GetForwardingPipelineConfigResponse get_pipe_cfg_res;
    get_pipe_cfg_req.set_device_id(1);
    get_pipe_cfg_req.set_response_type(p4::v1::GetForwardingPipelineConfigRequest::P4INFO_AND_COOKIE);
    
    grpc::Status status = service.get()->GetForwardingPipelineConfig(context, get_pipe_cfg_req, &get_pipe_cfg_res);
    printf("Status %d\n", status.error_code());
    if (status.error_code() == 0) { // Success
        // Normally, we should take p4info from response and query table id with table name.
        // Since there is no such tools doing so, we can simply query and insert table id manually.
        // 
        p4::config::v1::P4Info p4info = get_pipe_cfg_res.config().p4info();
        std::cout << "Available tables: " << std::endl;
        for (auto table : p4info.tables()) {
            std::cout << "Table Name: " << table.preamble().name() << ", Table ID: " << table.preamble().id() << std::endl;
        }
        std::cout << "Available actions: " << std::endl;
        for (const auto& action : p4info.actions()) {
            std::cout << "Action Name: " << action.preamble().name() 
                    << ", Action ID: " << action.preamble().id() << std::endl;
        }
        //
        p4::v1::WriteRequest write_request;
        p4::v1::WriteResponse write_response;

        write_request.set_device_id(1);
        p4::v1::Uint128 *election_id = p4::v1::Uint128().New();
        election_id->set_high(0);
        election_id->set_low(1);
        
        write_request.set_allocated_election_id(election_id);
        
        p4::v1::Update* updates = write_request.add_updates();
        updates->set_type(p4::v1::Update_Type_INSERT); // Set the update type

        p4::v1::TableEntry *table_entry = new p4::v1::TableEntry();
        p4::v1::Entity *entity = new p4::v1::Entity();

        p4::v1::TableAction *table_action = new p4::v1::TableAction();
        p4::v1::Action *action = new p4::v1::Action();

        table_entry->set_table_id(FORWARD_TABLE_ID);
        auto matches = table_entry->add_match();
        matches->set_field_id(1); // dst_addr
        p4::v1::FieldMatch_Exact *match_field = new p4::v1::FieldMatch_Exact();
        std::string dst_addr = "\x1B\x54\x32\xFE\x88\x10";

        match_field->set_value(dst_addr);
        matches->set_allocated_exact(match_field);

        std::string port = "\x09";
        action->set_action_id(ACTION_ID);
        auto params = action->add_params();
        params->set_param_id(1);
        params->set_value(port);

        // this is super dumb, but that is how it works
        table_action->set_allocated_action(action);
        table_entry->set_allocated_action(table_action);

        entity->set_allocated_table_entry(table_entry);
        updates->set_allocated_entity(entity);
        delete(context);

        // p4::v1::StreamMessageRequest request;
        // p4::v1::MasterArbitrationUpdate* master_update = request.mutable_arbitration();
        // master_update->set_device_id(1);
        // p4::v1::Role* master_role = master_update->mutable_role();
        // master_update->set_allocated_role(master_role);
        
        // **Deliver StreamMessageRequest(Some problem)**
        // auto status = service.get()->StreamChannel(request);
        // if (status.ok()) {
        //     std::cout << "Successfully sent MasterArbitrationUpdate" << std::endl;
        // } else {
        //     std::cout << "Failed to send MasterArbitrationUpdate: " << status.error_message() << std::endl;
        // }

        context = new grpc::ClientContext();
        status = service.get()->Write(context, write_request, &write_response);
        std::cout<< write_request.DebugString() << std::endl; // This should use cout instead of printf
        if (!status.ok()) {
            std::cerr << "Error inserting table entry: " << status.error_message() << std::endl;
            std::cerr << "Error details: " << status.error_details() << std::endl;
        }
    }
    return 0;
}