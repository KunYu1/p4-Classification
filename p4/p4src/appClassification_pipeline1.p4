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
parser IngressParser_1(packet_in        pkt,
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
            // ipv4_type_t.UDP: parser_tcp;
            default: accept;
        }
    }

    state parser_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}


    /***************** M A T C H - A C T I O N  *********************/



control Ingress_1(
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
    }

    action send_next_pipeline() {
        ig_tm_md.ucast_egress_port = 48;
    }

    action send_same_pipeline() {
        ig_tm_md.ucast_egress_port = 4;
    }

    action send_cpu() {
        ig_tm_md.ucast_egress_port = 64;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
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
        meta.mirror_session = MIRROR_SESSION_NUMBER_1;    
        meta.mirror_header_type = HEADER_TYPE_MIRROR_INGRESS;     
        meta.mirror_header_info = (header_info_t)ING_PORT_MIRROR;           
    }
    // =============== mirror ===============


    apply {                
        if (hdr.ipv4.isValid()) {  
            // recirculate from pipe1
            if (hdr.tcp.isValid() && ig_intr_md.ingress_port == 12) {
                ig_cpu_mirror();         
            } 
            ipv4_host.apply();
            if (ig_intr_md.ingress_port == 32) {
                send_same_pipeline();
            } else {
                send_next_pipeline();
            }
        }
        else{
            // Mirrored pkt from pipe2
            send_cpu();
        }
    }
}

/*********************  D E P A R S E R  ************************/
#ifdef FLEXIBLE_HEADERS
#define PAD(field)  field
#else
#define PAD(field)  0, field
#endif


control IngressDeparser_1(packet_out pkt,
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

parser EgressParser_1(packet_in        pkt,
    /* User */
    out my_egress_headers_1_t          hdr,
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
            ipv4_type_t.UDP: parser_tcp;
            default: accept;
        }
    }

    state parser_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    
}

    /***************** M A T C H - A C T I O N  *********************/
    


control Egress_1(
    /* User */
    inout my_egress_headers_1_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    cal_five_tuple_hash_1(coeff=0x04C11DB7, reverse=false) session_hash;  // CRC32    
    cal_five_tuple_hash_1(coeff=0x04C11DB7, reverse=true) rev_session_hash;  // CRC32    
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
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_cur_index; // index: session_hash
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<2>>(hash_mapping_cur_index)
        hash_mapping_cur_index_read_action = {
            void apply(inout bit<16> register_data, out bit<2> result) {
                if (register_data == meta.tmp_vars.rev_session_hash_value) {
                    result = 1;     
                } else {
                    result = 0;
                }      
            }
        };
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<2>>(hash_mapping_cur_index)
        hash_mapping_cur_index_write_action = {
            void apply(inout bit<16> register_data, out bit<2> result) {      
                register_data = meta.tmp_vars.rev_session_hash_value;                           
            }
        };

    /*  
     *   result:
     *       the mean of each bit:
     *          bit 0: check if register has a value
     *          bit 1: check if the element is matched
     *       
     *       the mean of result:
     *          11 => match success    
     *          00 => put new value in register                   
     *          01 => no match (only one function) or hash collision (two function have same answer)
     */
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_rev_cur_index; // index: rev_session_hash
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<2>>(hash_mapping_rev_cur_index)
        hash_mapping_rev_cur_index_read_action = {
            void apply(inout bit<16> register_data, out bit<2> result) {        
                if (register_data == meta.tmp_vars.rev_session_hash_value) {
                    result = 1;     
                } else {
                    result = 0;
                }              
            }
        };
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<2>>(hash_mapping_rev_cur_index)
        hash_mapping_rev_cur_index_write_action = {
            void apply(inout bit<16> register_data, out bit<2> result) {        
                register_data =  meta.tmp_vars.session_hash_value;   
            }
        };



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

    /*  
     *   Packet forward tv size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_pkt_size)
        hash_mapping_tv_reg_fwd_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(is_fwd){
                    register_data = pkt_length;
                }
                result = register_data;   
            }
        };
    

    /*  
     *   Packet backward tv size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_pkt_size)
        hash_mapping_tv_reg_bwd_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(!is_fwd){
                    register_data = pkt_length;
                }
                result = register_data;   
            }
        };


    /*  
     *   Packet forward tv total size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_total_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_total_pkt_size)
        hash_mapping_tv_reg_fwd_total_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {  
                if(is_fwd){ 
                    register_data = register_data + pkt_length;
                }
                result = register_data;   
            }
        };
    

    /*  
     *   Packet backward tv total size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_total_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_total_pkt_size)
        hash_mapping_tv_reg_bwd_total_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(!is_fwd){
                    register_data = register_data + pkt_length;
                }
                result = register_data;   
            }
        };


    /*  
     *   Packet forward tv min size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_min_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_min_pkt_size)
        hash_mapping_tv_reg_fwd_min_pkt_size_update_action = {
            void apply(inout bit<16> register_data, out bit<16> result) { 
                if(register_data == 0 || register_data > pkt_length){
                    register_data = pkt_length;
                }      
                result = register_data;        
            }
        };
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_min_pkt_size)
        hash_mapping_tv_reg_fwd_min_pkt_size_read_action = {
            void apply(inout bit<16> register_data, out bit<16> result) { 
                result = register_data;
            }
        };

    /*  
     *   Packet backward tv min size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_min_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_min_pkt_size)
        hash_mapping_tv_reg_bwd_min_pkt_size_update_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(register_data == 0 || register_data > pkt_length){
                    register_data = pkt_length;
                }    
                result = register_data;        
            }
        };
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_min_pkt_size)
        hash_mapping_tv_reg_bwd_min_pkt_size_read_action = {
            void apply(inout bit<16> register_data, out bit<16> result) { 
                result = register_data;
            }
        };

    /*  
     *   Packet forward tv max size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_max_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_max_pkt_size)
        hash_mapping_tv_reg_fwd_max_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(is_fwd){
                    if(register_data < pkt_length){
                        register_data = pkt_length;
                    } 
                }
                result = register_data;        
            }
        };
    

    /*  
     *   Packet backward tv max size register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_max_pkt_size;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_max_pkt_size)
        hash_mapping_tv_reg_bwd_max_pkt_size_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(!is_fwd){
                    if(register_data < pkt_length){
                        register_data = pkt_length;
                    } 
                }
                result = register_data;        
            }
        };

    /*  
     *   Packet forward tv var size register
     */
    
    Register<var_pair_16_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_var_pkt_size;
    
    RegisterAction<var_pair_16_t, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_var_pkt_size)
        hash_mapping_tv_reg_fwd_var_pkt_size_update_action = {
            void apply(inout var_pair_16_t register_data, out bit<16> result) { 
                if(register_data.prev != 0){
                    if(pkt_length > register_data.prev){
                        register_data.var = pkt_length - register_data.prev;
                    }else{
                        register_data.var = register_data.prev - pkt_length;
                    }
                }
                register_data.prev = pkt_length;
                result = register_data.var;
            }
        };
    
    RegisterAction<var_pair_16_t, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_var_pkt_size)
        hash_mapping_tv_reg_fwd_var_pkt_size_read_action = {
            void apply(inout var_pair_16_t register_data, out bit<16> result) { 
                result = register_data.var;
            }
        };

    /*  
     *   Packet backward tv var size register
     */
    
    Register<var_pair_16_t, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_var_pkt_size;
    
    RegisterAction<var_pair_16_t, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_var_pkt_size)
        hash_mapping_tv_reg_bwd_var_pkt_size_update_action = {
            void apply(inout var_pair_16_t register_data, out bit<16> result) {  
                if(register_data.prev != 0){
                    if(pkt_length > register_data.prev){
                        register_data.var = pkt_length - register_data.prev;
                    }else{
                        register_data.var = register_data.prev - pkt_length;
                    }
                }
                register_data.prev = pkt_length;
                result = register_data.var;
            }
        };
    
    RegisterAction<var_pair_16_t, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_var_pkt_size)
        hash_mapping_tv_reg_bwd_var_pkt_size_read_action = {
            void apply(inout var_pair_16_t register_data, out bit<16> result) { 
                result = register_data.var;
            }
        };


    /*  
     *   Packet forward tv ttl register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_ttl;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_ttl)
        hash_mapping_tv_reg_fwd_ttl_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(is_fwd){
                    register_data = (bit<16>)hdr.ipv4.ttl;
                }
                result = register_data;   
            }
        };
          

    /*  
     *   Packet backward tv ttl register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_ttl;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_ttl)
        hash_mapping_tv_reg_bwd_ttl_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(!is_fwd){
                    register_data = (bit<16>)hdr.ipv4.ttl;
                }
                result = register_data;   
            }
        };
       

    /*  
     *   Packet forward tv total ttl register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_total_ttl;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_total_ttl)
        hash_mapping_tv_reg_fwd_total_ttl_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {  
                if(is_fwd){ 
                    register_data = register_data + (bit<16>)hdr.ipv4.ttl;
                }
                result = register_data;   
            }
        };
    

    /*  
     *   Packet backward tv total ttl register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_total_ttl;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_total_ttl)
        hash_mapping_tv_reg_bwd_total_ttl_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(!is_fwd){
                    register_data = register_data + (bit<16>)hdr.ipv4.ttl;
                }
                result = register_data;   
            }
        };

    /*  
     *   Packet forward tv min ttl register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_min_ttl;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_min_ttl)
        hash_mapping_tv_reg_fwd_min_ttl_update_action = {
            void apply(inout bit<16> register_data, out bit<16> result) { 
                if(register_data == 0 || register_data > (bit<16>)hdr.ipv4.ttl){
                    register_data = (bit<16>)hdr.ipv4.ttl;
                }      
                result = register_data;        
            }
        };

    /*  
     *   Packet backward tv min ttl register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_min_ttl;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_min_ttl)
        hash_mapping_tv_reg_bwd_min_ttl_update_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(register_data == 0 || register_data > (bit<16>)hdr.ipv4.ttl){
                    register_data = (bit<16>)hdr.ipv4.ttl;
                }    
                result = register_data;        
            }
        };

    /*  
     *   Packet forward tv max ttl register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_fwd_max_ttl;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_fwd_max_ttl)
        hash_mapping_tv_reg_fwd_max_ttl_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(is_fwd){
                    if(register_data < (bit<16>)hdr.ipv4.ttl){
                        register_data = (bit<16>)hdr.ipv4.ttl;
                    } 
                }
                result = register_data;        
            }
        };
    

    /*  
     *   Packet backward tv max ttl register
     */
    
    Register<bit<16>, number_of_hash_registers_t>(NUMBER_OF_HASH_REGISTERS_DEC) hash_mapping_tv_reg_bwd_max_ttl;
    
    RegisterAction<bit<16>, number_of_hash_registers_t, bit<16>>(hash_mapping_tv_reg_bwd_max_ttl)
        hash_mapping_tv_reg_bwd_max_ttl_action = {
            void apply(inout bit<16> register_data, out bit<16> result) {   
                if(!is_fwd){
                    if(register_data < (bit<16>)hdr.ipv4.ttl){
                        register_data = (bit<16>)hdr.ipv4.ttl;
                    } 
                }
                result = register_data;        
            }
        };



    // ===================== session ID ======================
// ======================= REGISTERS =======================


// ----------------------- ACTIONS -----------------------   
    action send_to_cpu() {
        // hdr.to_cpu_tv.setValid();
        hdr.to_cpu_tv.mac_src = 48w0;
        hdr.to_cpu_tv.mac_dst = 48w0;
        hdr.to_cpu_tv.ether_type = 16w0xFFFF;
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
                // ---------------- get session id --------------------
                session_hash.apply(hdr, meta.tmp_vars.session_hash_value[14:0]);
                rev_session_hash.apply(hdr, meta.tmp_vars.rev_session_hash_value[14:0]);

                if(!meta.ing_port_mirror.isValid()) {
                    if(hdr.tcp.myctrl.count == 0){
                        hdr.tcp.myctrl.count = 1;
                        bit<2> tmp; 
                        bit<2> tmp2;
                        tmp = hash_mapping_cur_index_read_action.execute(meta.tmp_vars.session_hash_value[14:0]);
                        tmp2 = hash_mapping_rev_cur_index_read_action.execute(meta.tmp_vars.session_hash_value[14:0]);                                              
                        if (tmp == 2w0b01 && tmp2 != 2w0b01) {                         
                            hdr.tcp.myctrl.is_fwd = 1;      
                            hdr.tcp.myctrl.need_write = 0;             
                        } else if (tmp != 2w0b01 && tmp2 == 2w0b01) {                      
                            hdr.tcp.myctrl.is_fwd = 0;  
                            hdr.tcp.myctrl.need_write = 0;                     
                        } else {
                            hdr.tcp.myctrl.is_fwd = 1;
                            hdr.tcp.myctrl.need_write = 1;   
                        }
                    } else if(hdr.tcp.myctrl.need_write == 1){
                        hash_mapping_cur_index_write_action.execute(meta.tmp_vars.session_hash_value[14:0]);
                        hash_mapping_rev_cur_index_write_action.execute(meta.tmp_vars.rev_session_hash_value[14:0]);                                              
                    }
                } else { // mirror packet
                    send_to_cpu();
                    bit<2> tmp; 
                    bit<2> tmp2;
                    tmp = hash_mapping_cur_index_read_action.execute(meta.tmp_vars.session_hash_value[14:0]);
                    tmp2 = hash_mapping_rev_cur_index_read_action.execute(meta.tmp_vars.session_hash_value[14:0]);                                              
                    if (tmp == 2w0b01 && tmp2 != 2w0b01) {                         
                        is_fwd = true;              
                    } else if (tmp != 2w0b01 && tmp2 == 2w0b01) {                      
                        is_fwd = false;                    
                    } else {
                        is_fwd = true;
                    }
                    // session_id = meta.tmp_vars.session_hash_value;
                    if(is_fwd){    
                        session_id = meta.tmp_vars.session_hash_value[14:0];                
                    }else{
                        session_id = meta.tmp_vars.rev_session_hash_value[14:0];                
                    }

                    meta.tmp_vars.pkt_count = hash_mapping_reg_pkt_count_action.execute(session_id);
                   

                    if(meta.tmp_vars.pkt_count == 0) {
         
                        meta.tmp_vars.var_pkt_size = 0;
                        meta.tmp_vars.var_ttl = 0;
                        meta.tmp_vars.var_window = 0;
                        meta.tmp_vars.var_l4_payload_size = 0;

                    }

                    if((meta.tmp_vars.pkt_count) & (bit<16>)0b1111111111111000 == 0){
                        hdr.to_cpu_tv.setValid();
                    }


                    // Session Infos
                    hdr.to_cpu_tv.session_id = (bit<16>)session_id;

                    hdr.to_cpu_tv.fwd_id = (bit<16>)meta.tmp_vars.session_hash_value;
                    hdr.to_cpu_tv.bwd_id = (bit<16>)meta.tmp_vars.rev_session_hash_value;

                    hdr.to_cpu_tv.pkt_type = TV_PACKET_TYPE;
                    hdr.to_cpu_tv.reg_pkt_count = meta.tmp_vars.pkt_count;
                    


                    // TV Features
 
 
                    hdr.to_cpu_tv.tv_reg_fwd_pkt_size = hash_mapping_tv_reg_fwd_pkt_size_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_bwd_pkt_size = hash_mapping_tv_reg_bwd_pkt_size_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_fwd_total_pkt_size = hash_mapping_tv_reg_fwd_total_pkt_size_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_bwd_total_pkt_size = hash_mapping_tv_reg_bwd_total_pkt_size_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_fwd_max_pkt_size = hash_mapping_tv_reg_fwd_max_pkt_size_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_bwd_max_pkt_size = hash_mapping_tv_reg_bwd_max_pkt_size_action.execute(session_id);

                    hdr.to_cpu_tv.tv_reg_fwd_ttl = hash_mapping_tv_reg_fwd_ttl_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_bwd_ttl = hash_mapping_tv_reg_bwd_ttl_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_fwd_total_ttl = hash_mapping_tv_reg_fwd_total_ttl_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_bwd_total_ttl = hash_mapping_tv_reg_bwd_total_ttl_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_fwd_max_ttl = hash_mapping_tv_reg_fwd_max_ttl_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_bwd_max_ttl = hash_mapping_tv_reg_bwd_max_ttl_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_fwd_min_ttl = hash_mapping_tv_reg_fwd_min_ttl_update_action.execute(session_id);
                    hdr.to_cpu_tv.tv_reg_bwd_min_ttl = hash_mapping_tv_reg_bwd_min_ttl_update_action.execute(session_id);
                    
                    
                    if(is_fwd){    
                        hdr.to_cpu_tv.reg_is_fwd = 1;

                        hdr.to_cpu_tv.tv_reg_fwd_min_pkt_size = hash_mapping_tv_reg_fwd_min_pkt_size_update_action.execute(session_id);
                        hdr.to_cpu_tv.tv_reg_bwd_min_pkt_size = hash_mapping_tv_reg_bwd_min_pkt_size_read_action.execute(session_id);
                        hdr.to_cpu_tv.tv_reg_fwd_var_pkt_size = hash_mapping_tv_reg_fwd_var_pkt_size_update_action.execute(session_id);
                        hdr.to_cpu_tv.tv_reg_bwd_var_pkt_size = hash_mapping_tv_reg_bwd_var_pkt_size_read_action.execute(session_id);
                        
                    }else{
                        hdr.to_cpu_tv.reg_is_fwd = 0;

                        hdr.to_cpu_tv.tv_reg_fwd_min_pkt_size = hash_mapping_tv_reg_fwd_min_pkt_size_read_action.execute(session_id);
                        hdr.to_cpu_tv.tv_reg_bwd_min_pkt_size = hash_mapping_tv_reg_bwd_min_pkt_size_update_action.execute(session_id);
                        hdr.to_cpu_tv.tv_reg_fwd_var_pkt_size = hash_mapping_tv_reg_fwd_var_pkt_size_read_action.execute(session_id);
                        hdr.to_cpu_tv.tv_reg_bwd_var_pkt_size = hash_mapping_tv_reg_bwd_var_pkt_size_update_action.execute(session_id);
                        
                    }

                    disable_useless_header();
                // ================ get session id ====================
                }
            }
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser_1(packet_out pkt,
    /* User */
    inout my_egress_headers_1_t                     hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}
