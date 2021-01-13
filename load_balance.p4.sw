/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_WECMP = 0x1234;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header wecmp_t{
    bit<8> src_sw_id;
    bit<8> selected_path_id;
    bit<8> tag_path_id;
    bit<8> max_utilization;
}

struct metadata {
    bit<8> tag_id;
    bit<8> position;
    bit<8> output_tag_id;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    wecmp_t    wecmp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_WECMP: parse_wecmp;
            default: accept;
        }
    }
    state parse_wecmp {
        packet.extract(hdr.wecmp);
        transition parse_ipv4;
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /* config */
    action set_config_parameters(bit<8> id, bit<8> position) {
        meta.tag_id = id;
        meta.position = position;
    }
    table switch_config_params {
        actions = {
            set_config_parameters;
        }
        size = 1;
    }

    /* for ipv4 */
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    /* for wecmp */
    action tag_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }
    table output_tag_id_exact {
        key = {
            meta.output_tag_id: exact;
        }
        actions = {
            drop;
            tag_forward;
        }
        size = 1024;
        default_action = drop();
    }

    action get_path_id(){
        // get path id
        bit<8> output_id;
        output_id = hdr.wecmp.selected_path_id;
        output_id = output_id >> 1;
        output_id = output_id & 1;
        meta.output_tag_id = output_id;
    }

    /*action tor_forward(port){
        standard_metadata.egress_spec = port;
    }

    action path_forward(port){
        // get path id
        bit<8> output_id;
        output_id = hdr.wecmp.selected_path_id;
        output_id = output_id >> 1;
        output_id = output_id & 1;
        meta.output_tag_id = output_id;
        output_tag_id_exact.apply();
    }

    table dir_tag_exact{
        key = {
            meta.tag_id: exact;
            hdr.wecmp.src_sw_id: exact;
        }
        actions = {
            drop;
            path_forward;
            tor_forward;
        }
        size = 1024;
        default_action = drop();
    }*/

    apply {
        // configure
        switch_config_params.apply();

        if(hdr.wecmp.isValid()){
            // sent to TOR
            if(meta.position == 2){
                if(hdr.wecmp.src_sw_id == 1){
                    standard_metadata.egress_spec = 3;
                }
                else{
                    get_path_id();
                    output_tag_id_exact.apply();
                }
            }
            else if(meta.position == 1){
                if(hdr.wecmp.src_sw_id == 2){
                    standard_metadata.egress_spec = 3;
                }
                else{
                    get_path_id();
                    output_tag_id_exact.apply();
                }
            }
        }
        else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.wecmp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
