/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 *************************************************************************/

#define MAX_REGISTER_SIZE_BIT (64)
#define MIN_REGISTER_SIZE_BIT (8)
#define NUMBER_OF_HASH_REGISTERS_BIT (15) 
#define NUMBER_OF_TSTAMP_BIT (32) 


#define TV_PACKET_TYPE (3)
#define SS_PACKET_TYPE (4)



//#define NUMBER_OF_HASH_REGISTERS_DEC (2^(NUMBER_OF_HASH_REGISTERS_BIT)) // error
// #define NUMBER_OF_HASH_REGISTERS_DEC (65536) // 2 ^ NUMBER_OF_HASH_REGISTERS_BIT
#define NUMBER_OF_HASH_REGISTERS_DEC (32768) // 2 ^ NUMBER_OF_HASH_REGISTERS_BIT 


typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<MAX_REGISTER_SIZE_BIT> max_register_size_t;
typedef bit<NUMBER_OF_HASH_REGISTERS_BIT> number_of_hash_registers_t;
typedef bit<NUMBER_OF_TSTAMP_BIT> number_of_tstamp_t;
typedef bit<MIN_REGISTER_SIZE_BIT> min_register_size_t;



const PortId_t CPU_PORT = 64;
const int IPV4_HOST_SIZE = 65536;
const int IPV4_LPM_SIZE  = 12288;
const int MIRROR_SESSION_NUMBER_1 = 5;
const int MIRROR_SESSION_NUMBER_2 = 6;


struct register_t {
    bit<32> bottom;
    bit<32> top;
}

struct control_t {
    bit<1> count;
    bit<1> is_fwd;
    bit<1> need_write;
}

struct var_pair_32_t{
    bit<32> prev;
    bit<32> var;
}

struct var_pair_16_t{
    bit<16> prev;
    bit<16> var;
}

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    IPV6 = 0x86DD
}

enum bit<8> ipv4_type_t {
    TCP = 0x06,
    UDP = 0x11
}


/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    control_t myctrl;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

    /***********************  H E A D E R S  ************************/

header to_cpu_tv_h {    
    bit<48> mac_src;
    bit<48> mac_dst;
    bit<16> ether_type;

    bit<16> session_id; 
    bit<16> fwd_id;
    bit<16> bwd_id;

    bit<16> pkt_type;    
    bit<16> reg_pkt_count;
    bit<16> reg_is_fwd;

    bit<16> tv_reg_fwd_ttl;
    bit<16> tv_reg_bwd_ttl;
    bit<16> tv_reg_fwd_total_ttl;
    bit<16> tv_reg_bwd_total_ttl;
    bit<16> tv_reg_fwd_min_ttl;
    bit<16> tv_reg_bwd_min_ttl;
    bit<16> tv_reg_fwd_max_ttl;
    bit<16> tv_reg_bwd_max_ttl;
    bit<16> tv_reg_fwd_var_ttl;
    bit<16> tv_reg_bwd_var_ttl;

    bit<16> tv_reg_fwd_pkt_size;
    bit<16> tv_reg_bwd_pkt_size;
    bit<16> tv_reg_fwd_total_pkt_size;
    bit<16> tv_reg_bwd_total_pkt_size;
    bit<16> tv_reg_fwd_min_pkt_size;
    bit<16> tv_reg_bwd_min_pkt_size;
    bit<16> tv_reg_fwd_max_pkt_size;
    bit<16> tv_reg_bwd_max_pkt_size;
    bit<16> tv_reg_fwd_var_pkt_size;
    bit<16> tv_reg_bwd_var_pkt_size;
}

header to_cpu_ss_h {  
    bit<48> mac_src;
    bit<48> mac_dst;
    bit<16> ether_type;

    bit<16> session_id; 
    bit<16> fwd_id;
    bit<16> bwd_id;

    bit<16> pkt_type;    
    
    bit<32> sae_reg_irtt;
    bit<16> sae_reg_service_type;

    bit<16> sae_reg_total_pkt_size;
    bit<16> sae_reg_min_pkt_size;
    bit<16> sae_reg_mean_pkt_size;
    bit<16> sae_reg_var_pkt_size;

    bit<32> sae_reg_total_window;
    bit<16> sae_reg_min_window;
    bit<16> sae_reg_max_window;
    bit<32> sae_reg_var_window;

    bit<16> sae_reg_total_l4_payload_size;
    bit<16> sae_reg_min_l4_payload_size;
    bit<16> sae_reg_max_l4_payload_size;
    bit<16> sae_reg_mean_l4_payload_size;
    bit<16> sae_reg_var_l4_payload_size;


    bit<8> sae_reg_total_is_rst_flag;
    bit<8> sae_reg_total_is_psh_flag;
    bit<8> sae_reg_total_is_keep_alive;
    bit<8> sae_reg_total_is_sync_flood;

}

header tmp_vars_h {
    bit<16> current_pkt_size;
    bit<16> session_hash_value;
    bit<16> rev_session_hash_value;
    bit<16> current_l4_payload;
    bit<16> l4_payload_tmp; 
    bit<8> sae_flags;   

    bit<16> ttl;
    bit<16> l4_payload;
    bit<8> is_syn;
    bit<8> is_rst_flag;
    bit<8> is_psh_flag;
    bit<8> is_ack_flag;

    bit<8> is_keep_alive;
    bit<8> is_keep_alive_ack;
    bit<8> is_sync_flood;


    bit<16> pkt_count;
    
    bit<16> var_pkt_size;
    bit<16> var_pkt_size_final_first;
    bit<16> var_pkt_size_sum;

    bit<16> var_ttl;
    bit<16> var_ttl_final_first;
    bit<16> var_ttl_sum;

    bit<16> var_window;
    bit<16> var_window_final_first;
    bit<32> var_window_sum;

    bit<16> var_l4_payload_size;
    bit<16> var_l4_payload_size_final_first;
    bit<16> var_l4_payload_size_sum;

    bit<16> tv_reg_fwd_min_pkt_size;
    bit<16> tv_reg_bwd_min_pkt_size;

}

/* Ingress mirroring information */
const MirrorType_t ING_PORT_MIRROR = 3;
const MirrorType_t EGR_PORT_MIRROR = 5;

/*** Internal Headers ***/
typedef bit<4> header_type_t;
typedef bit<4> header_info_t;

#define INTERNAL_HEADER         \
    header_type_t header_type;  \
    header_info_t header_info

const header_type_t HEADER_TYPE_BRIDGE         = 0xB;
const header_type_t HEADER_TYPE_MIRROR_INGRESS = 0xC;
const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 0xD;
const header_type_t HEADER_TYPE_RESUBMIT       = 0xA;

header inthdr_h {
    INTERNAL_HEADER;
}

header bridge_h {
    INTERNAL_HEADER;
}

header ing_port_mirror_h { // same as registers in ingress
    // NIC needs to work in promiscuous mode
    // the size must be divided by 8       
    // max size: 32 bytes (256 bits)
    INTERNAL_HEADER;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    bridge_h     bridge;
    ethernet_h   ethernet;    
    ipv4_h       ipv4;
    tcp_t        tcp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t { 
    // max size: 2048 bit   
    MirrorId_t     mirror_session;            
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info; 
}




struct my_egress_headers_1_t {
    to_cpu_tv_h  to_cpu_tv;
    ethernet_h   ethernet;          
    ipv4_h       ipv4;
    tcp_t        tcp;
}

struct my_egress_headers_2_t {
    to_cpu_ss_h  to_cpu_ss;
    ethernet_h   ethernet;          
    ipv4_h       ipv4;
    tcp_t        tcp;
}
    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    inthdr_h           inthdr;
    bridge_h           bridge;
    ing_port_mirror_h  ing_port_mirror;
    tmp_vars_h tmp_vars;
    MirrorId_t     mirror_session;            
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info; 
}

control cal_five_tuple_hash_1(in my_egress_headers_1_t hdr, out number_of_hash_registers_t hash_value)(bit<32> coeff, bool reverse)
{
    CRCPolynomial<bit<32>>(
        coeff, 
        true,
        false,
        false,
        0xFFFFFFFF,
        0xFFFFFFFF) poly;

    Hash<number_of_hash_registers_t>(HashAlgorithm_t.CUSTOM, poly) hash_algo;

    action do_five_tuple_hash() {
        hash_value = hash_algo.get({  // do hash 
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port
        });
    }

    action do_reverse_five_tuple_hash() {
        hash_value = hash_algo.get({  // do hash 
            hdr.ipv4.protocol,
            hdr.ipv4.dst_addr,
            hdr.ipv4.src_addr,
            hdr.tcp.dst_port,
            hdr.tcp.src_port
        });
    }

    apply {
        if (reverse) {
            do_reverse_five_tuple_hash();
        } else {
            do_five_tuple_hash();
        }
    }
}

control cal_five_tuple_hash_2(in my_egress_headers_2_t hdr, out number_of_hash_registers_t hash_value)(bit<32> coeff, bool reverse)
{
    CRCPolynomial<bit<32>>(
        coeff, 
        true,
        false,
        false,
        0xFFFFFFFF,
        0xFFFFFFFF) poly;

    Hash<number_of_hash_registers_t>(HashAlgorithm_t.CUSTOM, poly) hash_algo;

    action do_five_tuple_hash() {
        hash_value = hash_algo.get({  // do hash 
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port
        });
    }

    action do_reverse_five_tuple_hash() {
        hash_value = hash_algo.get({  // do hash 
            hdr.ipv4.protocol,
            hdr.ipv4.dst_addr,
            hdr.ipv4.src_addr,
            hdr.tcp.dst_port,
            hdr.tcp.src_port
        });
    }

    apply {
        if (reverse) {
            do_reverse_five_tuple_hash();
        } else {
            do_five_tuple_hash();
        }
    }
}