/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#ifndef __HEADER__
#define __HEADER__
#include "header.p4"
#endif


/***********************
Ingress register:(sae, only a feature need previous value to add itself in each 32-bit register)
    bit<64> sae1_result; // 0~15 bit: pktTotalSize, 16~31 bit: dst port, 32~47: windowMin, 48~63: windowMax    


***********************/



    /***********************  P A R S E R  **************************/
parser IngressParser_2(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition init_bridge_and_meta;
    }

    state init_bridge_and_meta {       
        hdr.bridge.setValid();
        hdr.bridge.header_type  = HEADER_TYPE_BRIDGE; 
        hdr.bridge.header_info  = 0;

        transition parse_ethernet;
    }


    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {            
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            ipv4_type_t.TCP: parser_tcp;
            default: accept;
        }
    }

    state parser_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}


    /***************** M A T C H - A C T I O N  *********************/



control Ingress_2(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,    
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{     
    // --------------- L3 forwaring table & action ----------------
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        // ig_tm_md.ucast_egress_port = 309;
        // ig_tm_md.ucast_egress_port = 56;
        // ig_tm_md.ucast_egress_port = 64;
        // ig_tm_md.ucast_egress_port = 316;
    }

    action drop() {
        // ig_tm_md.ucast_egress_port = 309;
        // ig_tm_md.ucast_egress_port = 56;
        // ig_tm_md.ucast_egress_port = 316;


        ig_dprsr_md.drop_ctl = 1;
    }

    action send_next_pipeline(){
        ig_tm_md.ucast_egress_port = 36;
        // ig_tm_md.ucast_egress_port = 56;
        // ig_tm_md.ucast_egress_port = 316;
    }


    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            send; drop;
        }

        size = IPV4_HOST_SIZE;
    }
    // =============== L3 forwaring table & action ================



    // --------------- mirror ---------------
    action ig_cpu_mirror() {
        ig_dprsr_md.mirror_type = ING_PORT_MIRROR;
        meta.mirror_session = MIRROR_SESSION_NUMBER_2;    
        meta.mirror_header_type = HEADER_TYPE_MIRROR_INGRESS;     
        meta.mirror_header_info = (header_info_t)ING_PORT_MIRROR;           
    }
    // =============== mirror ===============


    apply {                
        if (hdr.ipv4.isValid()) {            
            if (hdr.tcp.isValid()) {
                ig_cpu_mirror();                
            } 

            // forward the packet
            ipv4_host.apply();
            send_next_pipeline();
        }
        // else{             
        //     // ig_tm_md.ucast_egress_port = 56;
        //     ig_tm_md.ucast_egress_port = 316;
        // }
    }
}

/*********************  D E P A R S E R  ************************/
#ifdef FLEXIBLE_HEADERS
#define PAD(field)  field
#else
#define PAD(field)  0, field
#endif


control IngressDeparser_2(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Mirror() mirror_cpu;
    apply {
        if (ig_dprsr_md.mirror_type == ING_PORT_MIRROR) {
            mirror_cpu.emit<ing_port_mirror_h>(
                meta.mirror_session,
                {                    
                    meta.mirror_header_type, meta.mirror_header_info
                });
        }

        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


    /***********************  P A R S E R  **************************/

parser EgressParser_2(packet_in        pkt,
    /* User */
    out my_egress_headers_2_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {

        pkt.extract(eg_intr_md);        
        meta.inthdr = pkt.lookahead<inthdr_h>();
        
        transition select(meta.inthdr.header_type, meta.inthdr.header_info) {
            ( HEADER_TYPE_BRIDGE,         _ ) :
                           parse_ethernet;
            ( HEADER_TYPE_MIRROR_INGRESS, (header_info_t)ING_PORT_MIRROR ):
                           parse_ing_port_mirror;
            default : reject;
        }
    }

    state parse_ing_port_mirror {
        pkt.extract(meta.ing_port_mirror);
        transition parse_ethernet_mirror;
    } 

    state parse_ethernet {
        pkt.extract<inthdr_h>(_);
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {            
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }   

    state parse_ethernet_mirror {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {            
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }   

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            ipv4_type_t.TCP: parser_tcp;
            default: accept;
        }
    }

    state parser_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    
}

    /***************** M A T C H - A C T I O N  *********************/
    

control Egress_2(
    /* User */
    inout my_egress_headers_2_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    cal_five_tuple_hash_2(coeff=0x04C11DB7, reverse=false) session_hash;  // CRC32    
    cal_five_tuple_hash_2(coeff=0x04C11DB7, reverse=true) rev_session_hash;  // CRC32    
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy_16;
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy_16_2;
    bool is_hash_collision = false;
    bool is_fwd = false;
    bool is_bwd = true;
    number_of_hash_registers_t session_id = 0;
    bit<16> pkt_length;

// ----------------------- REGISTERS -----------------------
    // --------------------- session ID ----------------------    
    /*  
     *   result:
     *       bit 0: check if register has a value
     *       bit 1: check if the element is matched
     *   
     *       11 => match success    
     *       00 => put new value in register                   
     *       01 => no match (only one function) or hash collision (two function have same answer)
     */
    // Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_cur_index; // index: session_hash
    // RegisterAction<bit<16>, number_of_hash_registers_t, bit<2>>(hash_mapping_cur_index)
    //     hash_mapping_cur_index_action = {
    //         void apply(inout bit<16> register_data, out bit<2> result) {                                
    //             if (register_data == meta.tmp_vars.rev_session_hash_value) {
    //                 result = 2w0b11;              // it means that current flow is bwd flow.
    //             } else {
    //                 if (register_data == 0) {
    //                     register_data = meta.tmp_vars.rev_session_hash_value;                    
    //                     result = 2w0b00;
    //                 } else {
    //                     result = 2w0b01;
    //                 }                    
    //             }   
    //         }
    //     };

    // /*  
    //  *   result:
    //  *       the mean of each bit:
    //  *          bit 0: check if register has a value
    //  *          bit 1: check if the element is matched
    //  *       
    //  *       the mean of result:
    //  *          11 => match success    
    //  *          00 => put new value in register                   
    //  *          01 => no match (only one function) or hash collision (two function have same answer)
    //  */
    // Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_rev_cur_index; // index: rev_session_hash
    // RegisterAction<bit<16>, number_of_hash_registers_t, bit<2>>(hash_mapping_rev_cur_index)
    //     hash_mapping_rev_cur_index_action = {
    //         void apply(inout bit<16> register_data, out bit<2> result) {        
    //             if (register_data == meta.tmp_vars.rev_session_hash_value) {
    //                 result = 2w0b11;              // it means that current flow is bwd flow.
    //             } else {
    //                 if (register_data == 0) {
    //                     register_data = meta.tmp_vars.session_hash_value;                    
    //                     result = 2w0b00;
    //                 } else {
    //                     result = 2w0b01;
    //                 }                    
    //             }          
    //         }
    //     };



    /*  
     *   Packet Count register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_reg_pkt_count;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_reg_pkt_count)
        hash_mapping_reg_pkt_count_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {        
                result = register_data;        
                register_data = register_data + 1;
            }
        };



    
    // ----------------------- Packet Size Registers -----------------------   
    /*  
     *   Packet size total register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_total_pkt_size)
        hash_mapping_sae_reg_total_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {        
                register_data = register_data + pkt_length;
                result = register_data;        
            }
        };

    /*  
     *   Packet size min register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_min_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_min_pkt_size)
        hash_mapping_sae_reg_min_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {    
                if(register_data == 0 || register_data > pkt_length){
                    register_data = pkt_length;
                }    
                result = register_data;        
            }
        };

    /*  
     *   Packet size max register
     */
    
    // Register<number_of_hash_registers_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_max_pkt_size;
    
    // RegisterAction<number_of_hash_registers_t, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_max_pkt_size)
    //     hash_mapping_sae_reg_max_pkt_size_action = {
    //         void apply(inout number_of_hash_registers_t register_data, out bit<16> result) {   
    //             if(register_data < pkt_length){
    //                 register_data = pkt_length;
    //             } 
    //             result = register_data;        
    //         }
    //     };

    // Packet Size var calculation
    /*  
     *   Packet previous size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_prev_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_prev_pkt_size)
        hash_mapping_sae_reg_prev_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   

                if(pkt_length > register_data){
                    result = pkt_length - register_data;
                }else{
                    result = register_data - pkt_length;
                }

                register_data = pkt_length;
            }
        };

    /*  
     *   Packet size var register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_var_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_var_pkt_size)
        hash_mapping_sae_reg_var_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {        
                register_data = register_data + meta.tmp_vars.var_pkt_size;
                result = register_data;    
            }
        };

    /*  
     *   Packet first size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_first_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_first_pkt_size)
        hash_mapping_sae_reg_first_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {    
                if(meta.tmp_vars.pkt_count == 0){    
                    register_data = pkt_length;
                }
                if(pkt_length > register_data){
                    result = pkt_length - register_data;
                }else{
                    result = register_data - pkt_length;
                }  
            }
        };
    // ======================= Packet Size Registers =======================
    


    // ----------------------- Packet TTL Registers -----------------------   
    /*  
     *   Packet ttl total register
     */
    // Register<number_of_hash_registers_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_ttl;
    // RegisterAction<number_of_hash_registers_t, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_total_ttl)
    //     hash_mapping_sae_reg_total_ttl_action = {
    //         void apply(inout number_of_hash_registers_t register_data, out bit<16> result) {   
    //             register_data = register_data + (bit<16>)hdr.ipv4.ttl;
    //             result = (bit<16>)register_data;      
    //         }
    //     };

    /*  
     *   Packet ttl min register
     */
    // Register<number_of_hash_registers_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_min_ttl;
    // RegisterAction<number_of_hash_registers_t, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_min_ttl)
    //     hash_mapping_sae_reg_min_ttl_action = {
    //         void apply(inout number_of_hash_registers_t register_data, out bit<16> result) {    
    //             if(register_data == 0 || register_data > (bit<16>)hdr.ipv4.ttl){
    //                 register_data = (bit<16>)hdr.ipv4.ttl;
    //             }    
    //             result = (bit<16>)register_data;        
    //         }
    //     };

    /*  
     *   Packet ttl max register
     */
    // Register<number_of_hash_registers_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_max_ttl;
    // RegisterAction<number_of_hash_registers_t, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_max_ttl)
    //     hash_mapping_sae_reg_max_ttl_action = {
    //         void apply(inout number_of_hash_registers_t register_data, out bit<16> result) {   
    //             if(register_data < (bit<16>)hdr.ipv4.ttl){
    //                 register_data = (bit<16>)hdr.ipv4.ttl;
    //             } 
    //             result = (bit<16>)register_data;        
    //         }
    //     };

    /*  
     *   Packet previous ttl register
     */
    // Register<number_of_hash_registers_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_prev_ttl;
    // RegisterAction<number_of_hash_registers_t, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_prev_ttl)
    //     hash_mapping_sae_reg_prev_ttl_action = {
    //         void apply(inout number_of_hash_registers_t register_data, out bit<16> result) {  
    //             if(meta.tmp_vars.ttl > register_data){
    //                 result = meta.tmp_vars.ttl - register_data;
    //             }else{
    //                 result = register_data - meta.tmp_vars.ttl;
    //             }
    //             register_data = meta.tmp_vars.ttl;
    //         }
    //     };

    /*  
     *   Packet ttl var register
     */
    // Register<number_of_hash_registers_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_var_ttl;
    // RegisterAction<number_of_hash_registers_t, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_var_ttl)
    //     hash_mapping_sae_reg_var_ttl_action = {
    //         void apply(inout number_of_hash_registers_t register_data, out bit<16> result) {        
    //             register_data = register_data + meta.tmp_vars.var_ttl;
    //             result = register_data;    
    //         }
    //     };

    /*  
     *   Packet first ttl register
     */
    // Register<number_of_hash_registers_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_first_ttl;
    // RegisterAction<number_of_hash_registers_t, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_first_ttl)
    //     hash_mapping_sae_reg_first_ttl_action = {
    //         void apply(inout number_of_hash_registers_t register_data, out bit<16> result) {    
    //             if(meta.tmp_vars.pkt_count == 1){    
    //                 register_data = meta.tmp_vars.ttl;
    //             }
    //             if(meta.tmp_vars.ttl > register_data){
    //                 result = meta.tmp_vars.ttl - register_data;
    //             }else{
    //                 result = register_data - meta.tmp_vars.ttl;
    //             }  
    //         }
    //     };

    // ======================= Packet TTL Registers =======================
    


    // ----------------------- Packet Window Registers -----------------------   
    /*  
     *   Packet window total register
     */
    
    Register<bit<32>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_window;
    
    RegisterAction<bit<32>, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_total_window)
        hash_mapping_sae_reg_total_window_action = {
            void apply(inout bit<32> register_data, out bit<32> result) {   
                register_data = register_data + (bit<32>)hdr.tcp.window;
                result = register_data;      
            }
        };

    /*  
     *   Packet window min register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_min_window;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_min_window)
        hash_mapping_sae_reg_min_window_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {    
                if(register_data == 0 || register_data > hdr.tcp.window){
                    register_data = hdr.tcp.window;
                }    
                result = register_data;        
            }
        };

    /*  
     *   Packet window max register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_max_window;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_max_window)
        hash_mapping_sae_reg_max_window_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(register_data < hdr.tcp.window) {
                    register_data = hdr.tcp.window;
                } 
                result = register_data;        
            }
        };

    /*  
     *   Packet previous window register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_prev_window;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_prev_window)
        hash_mapping_sae_reg_prev_window_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   

                if(hdr.tcp.window > register_data){
                    result = hdr.tcp.window - register_data;
                }else{
                    result = register_data - hdr.tcp.window;
                }

                register_data = hdr.tcp.window;
            }
        };

    /*  
     *   Packet window var register
     */
    
    Register<bit<32>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_var_window;
    
    RegisterAction<bit<32>, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_var_window)
        hash_mapping_sae_reg_var_window_action = {
            void apply(inout bit<32> register_data, out bit<32> result) {        
                register_data = register_data + (bit<32>)meta.tmp_vars.var_window;
                result = register_data;    
            }
        };

    /*  
     *   Packet first window register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_first_window;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_first_window)
        hash_mapping_sae_reg_first_window_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {    
                if(meta.tmp_vars.pkt_count == 0){    
                    register_data = hdr.tcp.window;
                }
                if(hdr.tcp.window > register_data){
                    result = hdr.tcp.window - register_data;
                }else{
                    result = register_data - hdr.tcp.window;
                }  
            }
        };

    // ======================= Packet Window Registers =======================



    // ----------------------- Packet IAT Registers -----------------------   
    /*  
     *   Packet previous arrival time register
     */
    
    // Register<number_of_tstamp_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_prev_tstamp;
    
    // RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_prev_tstamp)
    //     hash_mapping_sae_reg_prev_tstamp_action = {
    //         void apply(inout number_of_tstamp_t register_data, out bit<32> result) {   
    //             result = (bit<32>)(eg_prsr_md.global_tstamp >> 10) - register_data;        
    //             register_data = (bit<32>)(eg_prsr_md.global_tstamp >> 10);
    //         }
    //     };


    /*  
     *   Packet iat total register
     */
    
    // Register<number_of_tstamp_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_iat;
    
    // RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_total_iat)
    //     hash_mapping_sae_reg_total_iat_action = {
    //         void apply(inout number_of_tstamp_t register_data, out bit<32> result) {   
    //             register_data = register_data + meta.tmp_vars.iat;
    //             result = register_data;
    //         }
    //     };

    /*  
     *   Packet iat min register
     */
    
    // Register<number_of_tstamp_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_min_iat;
    
    // RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_min_iat)
    //     hash_mapping_sae_reg_min_iat_action = {
    //         void apply(inout number_of_tstamp_t register_data, out bit<32> result) {    
    //             if(register_data == 0 || register_data > meta.tmp_vars.iat){
    //                 register_data = meta.tmp_vars.iat;
    //             }    
    //             result = register_data;    
    //         }
    //     };

    /*  
     *   Packet iat max register
     */
    
    // Register<number_of_tstamp_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_max_iat;
    
    // RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_max_iat)
    //     hash_mapping_sae_reg_max_iat_action = {
    //         void apply(inout number_of_tstamp_t register_data, out bit<32> result) {   
    //             if(register_data < meta.tmp_vars.iat){
    //                 register_data = meta.tmp_vars.iat;
    //             } 
    //             result = register_data; 
    //         }
    //     };

    /*  
     *   Packet previous iat register
     */
    
    // Register<number_of_tstamp_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_prev_iat;
    
    // RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_prev_iat)
    //     hash_mapping_sae_reg_prev_iat_action = {
    //         void apply(inout number_of_tstamp_t register_data, out bit<32> result) {   

    //             if(meta.tmp_vars.iat > register_data){
    //                 result = meta.tmp_vars.iat - register_data;
    //             }else{
    //                 result = register_data - meta.tmp_vars.iat;
    //             }

    //             register_data = meta.tmp_vars.iat;
    //         }
    //     };

    /*  
     *   Packet iat var register
     */
    
    // Register<number_of_tstamp_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_var_iat;
    
    // RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_var_iat)
    //     hash_mapping_sae_reg_var_iat_action = {
    //         void apply(inout number_of_tstamp_t register_data, out bit<32> result) {        
    //             register_data = register_data + meta.tmp_vars.var_iat;
    //             result = register_data;    
    //         }
    //     };

    /*  
     *   Packet first iat register
     */
    
    // Register<number_of_tstamp_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_first_iat;
    
    // RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_first_iat)
    //     hash_mapping_sae_reg_first_iat_action = {
    //         void apply(inout number_of_tstamp_t register_data, out bit<32> result) {    
    //             if(meta.tmp_vars.pkt_count == 1){    
    //                 register_data = meta.tmp_vars.iat;
    //             }
    //             if(meta.tmp_vars.iat > register_data){
    //                 result = meta.tmp_vars.iat - register_data;
    //             }else{
    //                 result = register_data - meta.tmp_vars.iat;
    //             }  
    //         }
    //     };

    // ======================= Packet IAT Registers =======================




    // ----------------------- Packet L4 Payload Registers -----------------------   
    /*  
     *   Packet l4_payload_size total register
     */
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_l4_payload_size;
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_total_l4_payload_size)
        hash_mapping_sae_reg_total_l4_payload_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                register_data = register_data + meta.tmp_vars.l4_payload;
                result = register_data;      
            }
        };

    /*  
     *   Packet l4_payload_size min register
     */
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_min_l4_payload_size;
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_min_l4_payload_size)
        hash_mapping_sae_reg_min_l4_payload_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {    
                if(register_data == 0 || register_data > meta.tmp_vars.l4_payload){
                    register_data = meta.tmp_vars.l4_payload;
                }    
                result = register_data;        
            }
        };

    /*  
     *   Packet l4_payload_size max register
     */
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_max_l4_payload_size;
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_max_l4_payload_size)
        hash_mapping_sae_reg_max_l4_payload_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(register_data < meta.tmp_vars.l4_payload) {
                    register_data = meta.tmp_vars.l4_payload;
                } 
                result = register_data;        
            }
        };

    /*  
     *   Packet previous l4_payload_size register
     */
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_prev_l4_payload_size;
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_prev_l4_payload_size)
        hash_mapping_sae_reg_prev_l4_payload_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   

                if(meta.tmp_vars.l4_payload > register_data){
                    result = meta.tmp_vars.l4_payload - register_data;
                }else{
                    result = register_data - meta.tmp_vars.l4_payload;
                }

                register_data = meta.tmp_vars.l4_payload;
            }
        };

    /*  
     *   Packet l4_payload_size var register
     */
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_var_l4_payload_size;
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_var_l4_payload_size)
        hash_mapping_sae_reg_var_l4_payload_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {        
                register_data = register_data + meta.tmp_vars.var_l4_payload_size;
                result = register_data;    
            }
        };

    /*  
     *   Packet first l4_payload_size register
     */
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_first_l4_payload_size;
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_sae_reg_first_l4_payload_size)
        hash_mapping_sae_reg_first_l4_payload_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {    
                if(meta.tmp_vars.pkt_count == 0){    
                    register_data = meta.tmp_vars.l4_payload;
                }
                if(meta.tmp_vars.l4_payload > register_data){
                    result = meta.tmp_vars.l4_payload - register_data;
                }else{
                    result = register_data - meta.tmp_vars.l4_payload;
                }  
            }
        };


    // ======================= Packet L4 Payload Registers =======================



    // ----------------------- Packet RST Flag Registers -----------------------   
    /*  
     *   Packet rst flag total register
     */
    Register<bit<8>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_is_rst_flag;
    RegisterAction<bit<8>, number_of_hash_registers_t, bit<8>>(hash_mapping_sae_reg_total_is_rst_flag)
        hash_mapping_sae_reg_total_is_rst_flag_action = {
            void apply(inout bit<8> register_data, out bit<8> result) {        
                register_data = register_data + meta.tmp_vars.is_rst_flag;
                result = register_data;        
            }
        };
    // ======================= Packet RST Flag Registers =======================


    // ----------------------- Packet PSH Flag Registers -----------------------   
    /*  
     *   Packet rst flag total register
     */
    Register<bit<8>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_is_psh_flag;
    RegisterAction<bit<8>, number_of_hash_registers_t, bit<8>>(hash_mapping_sae_reg_total_is_psh_flag)
        hash_mapping_sae_reg_total_is_psh_flag_action = {
            void apply(inout bit<8> register_data, out bit<8> result) {        
                register_data = register_data + meta.tmp_vars.is_psh_flag;
                result = register_data;        
            }
        };
    // ======================= Packet PSH Flag Registers =======================


    // ----------------------- Packet Keep Alive Registers -----------------------   
    /*  
     *   Packet keep alive total register
     */
    Register<bit<8>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_is_keep_alive;
    RegisterAction<bit<8>, number_of_hash_registers_t, bit<8>>(hash_mapping_sae_reg_total_is_keep_alive)
        hash_mapping_sae_reg_total_is_keep_alive_action = {
            void apply(inout bit<8> register_data, out bit<8> result) {        
                register_data = register_data + meta.tmp_vars.is_keep_alive;
                result = register_data;        
            }
        };
    // ======================= Packet Keep Alive Registers =======================


    // ----------------------- Packet Keep Alive ACK Registers -----------------------   
    /*  
     *   Packet keep alive ACK total register
     */
    // Register<bit<8>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_is_keep_alive_ack;
    // RegisterAction<bit<8>, number_of_hash_registers_t, bit<8>>(hash_mapping_sae_reg_total_is_keep_alive_ack)
    //     hash_mapping_sae_reg_total_is_keep_alive_ack_action = {
    //         void apply(inout bit<8> register_data, out bit<8> result) {        
    //             register_data = register_data + meta.tmp_vars.is_keep_alive_ack;
    //             result = register_data;        
    //         }
    //     };
    // ======================= Packet Keep Alive ACK Registers =======================


    // ----------------------- Packet Sync Flood Registers -----------------------   
    /*  
     *   Packet is syn register
     */
    Register<bit<8>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_prev_fwd_syn_flag;
    RegisterAction<bit<8>, number_of_hash_registers_t, bit<8>>(hash_mapping_tv_reg_prev_fwd_syn_flag)
        hash_mapping_tv_reg_prev_fwd_syn_flag_action = {
            void apply(inout bit<8> register_data, out bit<8> result) {   
                result = register_data;        
                if(is_fwd){
                    register_data = (bit<8>)meta.tmp_vars.is_syn;
                }     
            }
        };
    /*  
     *   Packet sync flood total register
     */
    Register<bit<8>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_total_is_sync_flood;
    RegisterAction<bit<8>, number_of_hash_registers_t, bit<8>>(hash_mapping_sae_reg_total_is_sync_flood)
        hash_mapping_sae_reg_total_is_sync_flood_action = {
            void apply(inout bit<8> register_data, out bit<8> result) {        
                register_data = register_data + meta.tmp_vars.is_sync_flood;
                result = register_data;        
            }
        };
    // ======================= Packet Sync Flood Registers =======================

    // ----------------------- Packet iRTT Registers ----------------------- 
    Register<number_of_tstamp_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_sae_reg_irtt_tstamp;
    RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_irtt_tstamp)
        hash_mapping_sae_reg_irtt_tstamp_set_first_action = {
            void apply(inout number_of_tstamp_t register_data, out bit<32> result) {          
                register_data = (bit<32>)(eg_prsr_md.global_tstamp >> 10);
            }
        }; 
    RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_irtt_tstamp)
        hash_mapping_sae_reg_irtt_tstamp_calculate_action = {
            void apply(inout number_of_tstamp_t register_data, out bit<32> result) {   
                register_data = (bit<32>)(eg_prsr_md.global_tstamp >> 10) - register_data;        
                result = register_data;
            }
        }; 
    RegisterAction<number_of_tstamp_t, number_of_hash_registers_t, bit<32>>(hash_mapping_sae_reg_irtt_tstamp)
        hash_mapping_sae_reg_irtt_tstamp_get_action = {
            void apply(inout number_of_tstamp_t register_data, out bit<32> result) {          
                result = register_data;
            }
        }; 
    // ======================= Packet iRTT Registers =======================



    // ===================== session ID ======================
// ======================= REGISTERS =======================


// ----------------------- ACTIONS -----------------------   
    action send_to_cpu() {
        // hdr.to_cpu_ss.setValid();
        hdr.to_cpu_ss.mac_src = 48w0;
        hdr.to_cpu_ss.mac_dst = 48w0;
        hdr.to_cpu_ss.ether_type = 16w0xFFFF;
    }

    action disable_useless_header() {
        // These fields don't been needed by cpu.
        hdr.ethernet.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
    }
// ======================= ACTIONS =======================

    apply {
        if (hdr.ipv4.isValid()) {
            pkt_length = hdr.ipv4.total_len;
            if (hdr.tcp.isValid()) { // TCP packet                
                if (meta.ing_port_mirror.isValid()) { // mirror packet
                    send_to_cpu();
                    

                    // ---------------- get session id --------------------
                    session_hash.apply(hdr, meta.tmp_vars.session_hash_value[14:0]);
                    rev_session_hash.apply(hdr, meta.tmp_vars.rev_session_hash_value[14:0]);
                                             
                    is_fwd = (bool)hdr.tcp.myctrl.is_fwd;            

                    // session_id = meta.tmp_vars.session_hash_value;
                    if(is_fwd){    
                        session_id = meta.tmp_vars.session_hash_value[14:0];                
                        hdr.to_cpu_ss.sae_reg_service_type = hdr.tcp.dst_port;
                    }else{
                        session_id = meta.tmp_vars.rev_session_hash_value[14:0];                
                        hdr.to_cpu_ss.sae_reg_service_type = hdr.tcp.src_port;
                    }



                    meta.tmp_vars.pkt_count = hash_mapping_reg_pkt_count_action.execute(session_id);
                    meta.tmp_vars.ttl = (bit<16>)hdr.ipv4.ttl;
                    // meta.tmp_vars.iat = hash_mapping_sae_reg_prev_tstamp_action.execute(session_id);

                    // bit<16> header_size_sum = ((bit<16>)(hdr.ipv4.ihl + hdr.tcp.data_offset));
                    bit<16> header_size_sum = (bit<16>)hdr.ipv4.ihl;
                    header_size_sum = header_size_sum << 2;
                    // header_size_sum = header_size_sum + 0x50;
                    meta.tmp_vars.l4_payload = hdr.ipv4.total_len - header_size_sum;

                    if(hdr.tcp.ctrl & (bit<6>)0b000100 != 0){
                        meta.tmp_vars.is_rst_flag = 1;
                    }
                    if(hdr.tcp.ctrl & (bit<6>)0b001000 != 0){
                        meta.tmp_vars.is_psh_flag = 1;
                    }
                    if(hdr.tcp.ctrl & (bit<6>)0b010000 != 0){
                        meta.tmp_vars.is_ack_flag = 1;
                    }

                    if(hdr.tcp.ctrl == (bit<6>)0b010000){
                        if(pkt_length & (bit<16>)0b1111111111111000 == 0){
                            meta.tmp_vars.is_keep_alive = 1;
                        }
                        // if(pkt_length & (bit<16>)0b1111111110000000 == 0){
                            // meta.tmp_vars.is_keep_alive = 1;
                        // }
                    }
                    
                    if(hdr.tcp.ctrl == (bit<6>)0b000010){
                        meta.tmp_vars.is_syn = 1;
                    }

                    if(hash_mapping_tv_reg_prev_fwd_syn_flag_action.execute(session_id) != 0){
                        if(meta.tmp_vars.is_syn != 0){
                            meta.tmp_vars.is_sync_flood = 1;
                        }
                    }
                   

                    meta.tmp_vars.var_pkt_size = hash_mapping_sae_reg_prev_pkt_size_action.execute(session_id);
                    // meta.tmp_vars.var_ttl = hash_mapping_sae_reg_prev_ttl_action.execute(session_id);
                    meta.tmp_vars.var_window = hash_mapping_sae_reg_prev_window_action.execute(session_id);
                    // meta.tmp_vars.var_iat = hash_mapping_sae_reg_prev_iat_action.execute(session_id);
                    meta.tmp_vars.var_l4_payload_size = hash_mapping_sae_reg_prev_l4_payload_size_action.execute(session_id);


                    meta.tmp_vars.var_pkt_size_final_first = hash_mapping_sae_reg_first_pkt_size_action.execute(session_id);
                    // meta.tmp_vars.var_ttl_final_first = hash_mapping_sae_reg_first_ttl_action.execute(session_id);
                    meta.tmp_vars.var_window_final_first = hash_mapping_sae_reg_first_window_action.execute(session_id);
                    // meta.tmp_vars.var_iat_final_first = hash_mapping_sae_reg_first_iat_action.execute(session_id);
                    meta.tmp_vars.var_l4_payload_size_final_first = hash_mapping_sae_reg_first_l4_payload_size_action.execute(session_id);

                    if(meta.tmp_vars.pkt_count == 0){

                        meta.tmp_vars.var_pkt_size = 0;
                        meta.tmp_vars.var_ttl = 0;
                        meta.tmp_vars.var_window = 0;
                        // meta.tmp_vars.var_iat = 0;
                        meta.tmp_vars.var_l4_payload_size = 0;

                        hash_mapping_sae_reg_irtt_tstamp_set_first_action.execute(session_id);

                    }else if(meta.tmp_vars.pkt_count == 2){
                        hash_mapping_sae_reg_irtt_tstamp_calculate_action.execute(session_id);
                    }else{
                        hdr.to_cpu_ss.sae_reg_irtt = hash_mapping_sae_reg_irtt_tstamp_get_action.execute(session_id);
                    }


                    meta.tmp_vars.var_pkt_size_sum = hash_mapping_sae_reg_var_pkt_size_action.execute(session_id) + meta.tmp_vars.var_pkt_size_final_first;
                    // meta.tmp_vars.var_ttl_sum = hash_mapping_sae_reg_var_ttl_action.execute(session_id) + meta.tmp_vars.var_ttl_final_first;
                    bit<32> tmp = (bit<32>)meta.tmp_vars.var_window_final_first;
                    meta.tmp_vars.var_window_sum = hash_mapping_sae_reg_var_window_action.execute(session_id) + tmp;
                    // meta.tmp_vars.var_iat_sum = hash_mapping_sae_reg_var_iat_action.execute(session_id) + meta.tmp_vars.var_iat_final_first;
                    meta.tmp_vars.var_l4_payload_size_sum = hash_mapping_sae_reg_var_l4_payload_size_action.execute(session_id) + meta.tmp_vars.var_l4_payload_size_final_first;

                    if(meta.tmp_vars.pkt_count == 7){
                        hdr.to_cpu_ss.setValid();
                    }

                    // Session Infos
                    hdr.to_cpu_ss.session_id = (bit<16>)session_id;

                    hdr.to_cpu_ss.fwd_id = (bit<16>)meta.tmp_vars.session_hash_value;
                    hdr.to_cpu_ss.bwd_id = (bit<16>)meta.tmp_vars.rev_session_hash_value;

                    hdr.to_cpu_ss.pkt_type = SS_PACKET_TYPE;


                    

                    
 



                    // SS Features
                    hdr.to_cpu_ss.sae_reg_total_pkt_size = hash_mapping_sae_reg_total_pkt_size_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_min_pkt_size = hash_mapping_sae_reg_min_pkt_size_action.execute(session_id);
                    // hdr.to_cpu_ss.sae_reg_max_pkt_size = hash_mapping_sae_reg_max_pkt_size_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_mean_pkt_size = (hdr.to_cpu_ss.sae_reg_total_pkt_size >> 3);
                    hdr.to_cpu_ss.sae_reg_var_pkt_size = (meta.tmp_vars.var_pkt_size_sum >> 3);

                    // hdr.to_cpu_ss.sae_reg_total_ttl = hash_mapping_sae_reg_total_ttl_action.execute(session_id);
                    // hdr.to_cpu_ss.sae_reg_min_ttl = hash_mapping_sae_reg_min_ttl_action.execute(session_id);
                    // hdr.to_cpu_ss.sae_reg_max_ttl = hash_mapping_sae_reg_max_ttl_action.execute(session_id);
                    // hdr.to_cpu_ss.sae_reg_mean_ttl = (hdr.to_cpu_ss.sae_reg_total_ttl >> 3);
                    // hdr.to_cpu_ss.sae_reg_var_ttl = (meta.tmp_vars.var_ttl_sum >> 3);

                    hdr.to_cpu_ss.sae_reg_total_window = hash_mapping_sae_reg_total_window_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_min_window = hash_mapping_sae_reg_min_window_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_max_window = hash_mapping_sae_reg_max_window_action.execute(session_id);
                    // hdr.to_cpu_ss.sae_reg_mean_window = hdr.to_cpu_ss.sae_reg_total_window[18:3];
                    hdr.to_cpu_ss.sae_reg_var_window = meta.tmp_vars.var_window_sum;

                    // hdr.to_cpu_ss.sae_reg_total_iat = hash_mapping_sae_reg_total_iat_action.execute(session_id);
                    // hdr.to_cpu_ss.sae_reg_min_iat = hash_mapping_sae_reg_min_iat_action.execute(session_id);
                    // hdr.to_cpu_ss.sae_reg_max_iat = hash_mapping_sae_reg_max_iat_action.execute(session_id);
                    // hdr.to_cpu_ss.sae_reg_mean_iat = (hdr.to_cpu_ss.sae_reg_total_iat >> 3);
                    // hdr.to_cpu_ss.sae_reg_var_iat = (meta.tmp_vars.var_iat_sum >> 3);

                    hdr.to_cpu_ss.sae_reg_total_l4_payload_size = hash_mapping_sae_reg_total_l4_payload_size_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_min_l4_payload_size = hash_mapping_sae_reg_min_l4_payload_size_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_max_l4_payload_size = hash_mapping_sae_reg_max_l4_payload_size_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_mean_l4_payload_size = (hdr.to_cpu_ss.sae_reg_total_l4_payload_size >> 3);
                    hdr.to_cpu_ss.sae_reg_var_l4_payload_size = (meta.tmp_vars.var_l4_payload_size_sum >> 3);

                    // hdr.to_cpu_ss.sae_reg_session_connection_time = hdr.to_cpu_ss.sae_reg_total_iat;

                    hdr.to_cpu_ss.sae_reg_total_is_rst_flag = hash_mapping_sae_reg_total_is_rst_flag_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_total_is_psh_flag = hash_mapping_sae_reg_total_is_psh_flag_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_total_is_keep_alive = hash_mapping_sae_reg_total_is_keep_alive_action.execute(session_id);
                    hdr.to_cpu_ss.sae_reg_total_is_sync_flood = hash_mapping_sae_reg_total_is_sync_flood_action.execute(session_id);



                    disable_useless_header();
                // ================ get session id ====================
                }
            }
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser_2(packet_out pkt,
    /* User */
    inout my_egress_headers_2_t                     hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}
