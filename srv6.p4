/* -*- mode: P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

#define MAX_PORTS 255

typedef bit<9> port_t;
const port_t CPU_PORT = 255;

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_length;
    bit<8>   next_header;
    bit<8>   hop_limit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}


header srv6_fixedpart_t {
    bit<8>   next_header;
    bit<8>   hdr_ext_len;
    bit<8>   routing_type;
    bit<8>   segments_left;
    bit<8>   last_entry;
    bit<8>   flags;
    bit<16>  tag;
}


#define MAX_IPV6_ADDRESSES  8
#define MAX_SRV6_METADATA   8

header srv6_seg_list_t {
    bit<128> dstAddr;
}
header srv6_tlv_metadata_t { // NOTE: fixed to be 64 bit length (8-octets)
    bit<8> type_data;
    bit<8> lenght;
    bit<48> data;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udp_length;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seq;
    bit<32> ack;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


struct headers_t {
    ethernet_t ethernet;
    ipv6_t     ipv6;
    ipv4_t     ipv4;
    srv6_fixedpart_t srv6_fixedpart;
    srv6_seg_list_t[MAX_IPV6_ADDRESSES] srv6_seg_list;
    srv6_tlv_metadata_t[MAX_SRV6_METADATA] srv6_tlv_metadata;
    udp_t      udp;
    tcp_t      tcp;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
}

struct metadata_t {
    bit<1> srv6_match;
    bit<4> num_srv6_addresses;
    bit<128> function_to_be_executed;
    bit<128> next_segment_identifier;
    srv6_tlv_metadata_t[MAX_SRV6_METADATA] vnf_metadata;
}

error {
    BadSRv6HdrExtLen,
    BadSRv6HdrExtLen2,
    BadSRv6MetadataLen
}


VNF_INCLUDE

parser ParserImpl(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t stdmeta)
{
    const bit<16> ETHERTYPE_IPV6 = 0x86dd;
    const bit<16> ETHERTYPE_IPV4 = 0x0800;
    const bit<8> IPPROTO_UDP = 17;
    const bit<8> IPPROTO_IPV4 = 4;
    const bit<8> IPPROTO_TCP = 6;
    const bit<8> IPPROTO_IPV6 = 41;
    const bit<8> IPPROTO_ICMP = 1;
    const bit<8> IPPROTO_ICMPv6 = 58;
    const bit<8> IPPROTO_IPV6EXTHDR_ROUTING = 43;

    bit<8> segments_remaining_to_parse;
    bit<8> metadata_remaining_to_parse;

    state start {
        transition select(stdmeta.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }
    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType) {
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP: parse_udp;
            IPPROTO_TCP: parse_tcp;
            default: accept;
        }
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select (hdr.ipv6.next_header) {
            IPPROTO_IPV6EXTHDR_ROUTING: parse_ipv6_exthdr_routing_fixedpart;
            IPPROTO_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_ipv6_exthdr_routing_fixedpart {
        packet.extract(hdr.srv6_fixedpart);
        // The hdr_ext_len is defined in RFC 8200 as: "Length of the
        // Routing header in 8-octet units, not including the first 8
        // octets."  The first 8 octets are in srv6_fixedpart in
        // this program.  This program is not intended to handle the
        // cases with options inside of the IPv6 Segment Routing
        // extension header, so the rest of the extension header is 1
        // or more IPv6 addresses, each counting as 2 groups of 8
        // octets in the hdr_ext_len field.

        // This program only handles SRv6 ext headers with one or more
        // IPv6 addresses in the segment list, and no options inside
        // the IPv6 extension header after that.  Thus hdr_ext_len
        // must be even, and not 0.  This example program is only
        // written to handle SRv6 headers with up to 8 such IPv6
        // addresses.
        verify(hdr.srv6_fixedpart.hdr_ext_len != 0, error.BadSRv6HdrExtLen);
        segments_remaining_to_parse = hdr.srv6_fixedpart.last_entry + 1; // Number of srv6 segments to parse

        // (hdr.srv6_fixedpart.hdr_ext_len - ((hdr.srv6.last_entry + 1)*2) is the number of TLV metadata to parse
        metadata_remaining_to_parse = (hdr.srv6_fixedpart.hdr_ext_len - ((hdr.srv6_fixedpart.last_entry + 1 ) << 1 ));
        transition select (segments_remaining_to_parse) {
            1: parse_srv6_one_segment;
            2: parse_srv6_one_segment;
            3: parse_srv6_one_segment;
            4: parse_srv6_one_segment;
            5: parse_srv6_one_segment;
            6: parse_srv6_one_segment;
            7: parse_srv6_one_segment;
            8: parse_srv6_one_segment;
            default: parse_srv6_bad_len;
        }
    }
    state parse_srv6_bad_len {
        verify(false, error.BadSRv6HdrExtLen);
        transition reject;
    }
    state parse_srv6_metadata_bad_len {
        verify(false, error.BadSRv6MetadataLen);
        transition reject;
    }
    state parse_srv6_one_segment {
        packet.extract(hdr.srv6_seg_list.next);
        segments_remaining_to_parse = segments_remaining_to_parse - 1;
        transition select (segments_remaining_to_parse) {
            0: parse_srv6_metadata;
            default: parse_srv6_one_segment;
        }
    }
    state parse_srv6_metadata {
        transition select(metadata_remaining_to_parse) {
            0: parse_ipv6_after_srv6;
            1: parse_srv6_one_metadata;
            2: parse_srv6_one_metadata;
            3: parse_srv6_one_metadata;
            4: parse_srv6_one_metadata;
            5: parse_srv6_one_metadata;
            6: parse_srv6_one_metadata;
            7: parse_srv6_one_metadata;
            8: parse_srv6_one_metadata;
            default: parse_srv6_metadata_bad_len;
        }
    }
    state parse_srv6_one_metadata {
        packet.extract(hdr.srv6_tlv_metadata.next);
        metadata_remaining_to_parse = metadata_remaining_to_parse - 1;
        transition select (metadata_remaining_to_parse) {
            0: parse_ipv6_after_srv6;
            default: parse_srv6_one_metadata;
        }
    }
    state parse_ipv6_after_srv6 {
        transition select (hdr.srv6_fixedpart.next_header) {
            IPPROTO_UDP: parse_udp;
            IPPROTO_TCP: parse_tcp;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control SRV6_control(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t stdmeta) {
    // ---------------------------------- Table matching on IPv6 dst addr -----------------------------
    action next_sid(){
        //Ideally the next sid is hdr.srv6_seg_list[hdr.srv6_fixedpart.segmentsLeft] but there is no possibility of using dynamic indeces on variable lenght parameters
        hdr.ipv6.dstAddr = meta.next_segment_identifier;
        hdr.srv6_fixedpart.segments_left = hdr.srv6_fixedpart.segments_left - 1;
    }

    action set_function_to_be_executed() {
        meta.function_to_be_executed = hdr.ipv6.dstAddr & 0x0000000000000000FFFFFFFFFFFFFFFF;
        meta.srv6_match = 0b1;
        next_sid();
    }

    direct_counter(CounterType.packets_and_bytes) cnt_srv6_e;
    table srv6_end { // localsid
        key = {
            hdr.ipv6.dstAddr : ternary;
        }
        actions = {
            @defaultonly NoAction;
            set_function_to_be_executed;
        }
        default_action = NoAction;
        counters = cnt_srv6_e;
    }
    // -----------------------------------------------------------------------------------------------

    // ---------------------------------- Table needed to set the next SID ---------------------------
    action set_nextsid_1() {
        meta.next_segment_identifier = hdr.srv6_seg_list[0].dstAddr;
    }
    action set_nextsid_2() {
        meta.next_segment_identifier = hdr.srv6_seg_list[1].dstAddr;
    }
    action set_nextsid_3() {
        meta.next_segment_identifier = hdr.srv6_seg_list[2].dstAddr;
    }
    action set_nextsid_4() {
        meta.next_segment_identifier = hdr.srv6_seg_list[3].dstAddr;
    }
    action set_nextsid_5() {
        meta.next_segment_identifier = hdr.srv6_seg_list[4].dstAddr;
    }
    action set_nextsid_6() {
        meta.next_segment_identifier = hdr.srv6_seg_list[5].dstAddr;
    }
    action set_nextsid_7() {
        meta.next_segment_identifier = hdr.srv6_seg_list[6].dstAddr;
    }
    action set_nextsid_8() {
        meta.next_segment_identifier = hdr.srv6_seg_list[7].dstAddr;
    }
    table srv6_set_nextsid { // helper table
        key = {
            hdr.srv6_fixedpart.segments_left : exact;
        }
        actions = {
            NoAction;
            set_nextsid_1;
            set_nextsid_2;
            set_nextsid_3;
            set_nextsid_4;
            set_nextsid_5;
            set_nextsid_6;
            set_nextsid_7;
            set_nextsid_8;
        }
        const default_action = NoAction;
        const entries = {
            (1) : set_nextsid_1();
            (2) : set_nextsid_2();
            (3) : set_nextsid_3();
            (4) : set_nextsid_4();
            (5) : set_nextsid_5();
            (6) : set_nextsid_6();
            (7) : set_nextsid_7();
            (8) : set_nextsid_8();
        }
    }
    // -----------------------------------------------------------------------------------------------

    // ------------------------ Table to fwd packet based on dst IPv6 address ------------------------
    action set_next_hop (bit<9> port) {
        stdmeta.egress_spec = port;
        meta.srv6_match = 0b1;
    }

    direct_counter(CounterType.packets_and_bytes) cnt_ipv6_next_hop;
    table ipv6_next_hop {
        key = {
            hdr.ipv6.dstAddr : exact;
        }
        actions = {
            NoAction;
            set_next_hop;
        }
        default_action = NoAction;
        counters = cnt_ipv6_next_hop;
    }
    // -----------------------------------------------------------------------------------------------

    action remove_srv6_header() {
        hdr.ipv6.payload_length = hdr.ipv6.payload_length - (bit<16>)((hdr.srv6_fixedpart.hdr_ext_len+1) << 3); // Remove the whole dimension of the extension header (SID list + fixed header)
        hdr.ipv6.next_header = hdr.srv6_fixedpart.next_header;
        hdr.srv6_seg_list[0].setInvalid();
        hdr.srv6_seg_list[1].setInvalid();
        hdr.srv6_seg_list[2].setInvalid();
        hdr.srv6_seg_list[3].setInvalid();
        hdr.srv6_seg_list[4].setInvalid();
        hdr.srv6_seg_list[5].setInvalid();
        hdr.srv6_seg_list[6].setInvalid();
        hdr.srv6_seg_list[7].setInvalid();
        hdr.srv6_fixedpart.setInvalid();
    }


    apply {
        // ------------------------------------------------
        // This first if is needed because array indeces must be constant and in this way we need to preconfigure which is the next sid
        if (hdr.srv6_fixedpart.isValid()) {
            srv6_set_nextsid.apply();
        }

        if (hdr.ipv6.isValid()) {
            srv6_end.apply();
            // Check if we need to remove the srv6 header
            if(hdr.srv6_fixedpart.isValid() && hdr.srv6_fixedpart.segments_left == 0){
                remove_srv6_header();
            }
            // Decide about the next hop based on the dst address ipv6
            ipv6_next_hop.apply();

            // Check if Advanced functionalities are needed
            if(meta.function_to_be_executed != 0) {
                // Check for metadata. srv6 metadata should be saved on users metadata and invalidated
                if (hdr.srv6_tlv_metadata[0].isValid()) {
                    meta.vnf_metadata[0] = hdr.srv6_tlv_metadata[0];
                    hdr.srv6_tlv_metadata[0].setInvalid();
                    hdr.srv6_fixedpart.hdr_ext_len = hdr.srv6_fixedpart.hdr_ext_len - 1;
                    hdr.ipv6.payload_length = hdr.ipv6.payload_length -8;
                }
                if (hdr.srv6_tlv_metadata[1].isValid()) {
                    // There is metadata. Save the metadata on users metadata
                    meta.vnf_metadata[1] = hdr.srv6_tlv_metadata[1];
                    hdr.srv6_tlv_metadata[1].setInvalid();
                    hdr.srv6_fixedpart.hdr_ext_len = hdr.srv6_fixedpart.hdr_ext_len - 1;
                    hdr.ipv6.payload_length = hdr.ipv6.payload_length -8;
                }
                if (hdr.srv6_tlv_metadata[2].isValid()) {
                    meta.vnf_metadata[2] = hdr.srv6_tlv_metadata[2];
                    hdr.srv6_tlv_metadata[2].setInvalid();
                    hdr.srv6_fixedpart.hdr_ext_len = hdr.srv6_fixedpart.hdr_ext_len - 1;
                    hdr.ipv6.payload_length = hdr.ipv6.payload_length -8;
                }
                if (hdr.srv6_tlv_metadata[3].isValid()) {
                    // There is metadata. Save the metadata on users metadata
                    meta.vnf_metadata[3] = hdr.srv6_tlv_metadata[3];
                    hdr.srv6_tlv_metadata[3].setInvalid();
                    hdr.srv6_fixedpart.hdr_ext_len = hdr.srv6_fixedpart.hdr_ext_len - 1;
                    hdr.ipv6.payload_length = hdr.ipv6.payload_length -8;
                }
                if (hdr.srv6_tlv_metadata[4].isValid()) {
                    meta.vnf_metadata[4] = hdr.srv6_tlv_metadata[4];
                    hdr.srv6_tlv_metadata[4].setInvalid();
                    hdr.srv6_fixedpart.hdr_ext_len = hdr.srv6_fixedpart.hdr_ext_len - 1;
                    hdr.ipv6.payload_length = hdr.ipv6.payload_length -8;
                }
                if (hdr.srv6_tlv_metadata[5].isValid()) {
                    // There is metadata. Save the metadata on users metadata
                    meta.vnf_metadata[5] = hdr.srv6_tlv_metadata[5];
                    hdr.srv6_tlv_metadata[5].setInvalid();
                    hdr.srv6_fixedpart.hdr_ext_len = hdr.srv6_fixedpart.hdr_ext_len - 1;
                    hdr.ipv6.payload_length = hdr.ipv6.payload_length -8;
                }
                if (hdr.srv6_tlv_metadata[6].isValid()) {
                    meta.vnf_metadata[6] = hdr.srv6_tlv_metadata[6];
                    hdr.srv6_tlv_metadata[6].setInvalid();
                    hdr.srv6_fixedpart.hdr_ext_len = hdr.srv6_fixedpart.hdr_ext_len - 1;
                    hdr.ipv6.payload_length = hdr.ipv6.payload_length -8;
                }
                if (hdr.srv6_tlv_metadata[7].isValid()) {
                    // There is metadata. Save the metadata on users metadata
                    meta.vnf_metadata[7] = hdr.srv6_tlv_metadata[7];
                    hdr.srv6_tlv_metadata[7].setInvalid();
                    hdr.srv6_fixedpart.hdr_ext_len = hdr.srv6_fixedpart.hdr_ext_len - 1;
                    hdr.ipv6.payload_length = hdr.ipv6.payload_length -8;
                }
            }
        // SRV6 functionality ended: with this implementation the dimension of the packet is modified but it is maintained coherent in ipv6 and srv6 header
        }
    }
}


control ingress(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t stdmeta)
{
    // ------------------------ Table and counter to be compatible with ONOS l2 fwd ------------------
    // We use these counters to count packets/bytes received/sent on each port.
    // For each counter we instantiate a number of cells equal to MAX_PORTS.
    counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

    action send_to_cpu() {
        stdmeta.egress_spec = CPU_PORT;
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = stdmeta.ingress_port;
    }

    action set_out_port(port_t port) {
        // Specifies the output port for this packet by setting the
        // corresponding metadata.
        stdmeta.egress_spec = port;
    }

    action _drop() {
        mark_to_drop();
    }
    direct_counter(CounterType.packets_and_bytes) l2_fwd_counter;
    table t_l2_fwd {
        key = {
            stdmeta.ingress_port  : ternary;
            hdr.ethernet.dstAddr           : ternary;
            hdr.ethernet.srcAddr           : ternary;
            hdr.ethernet.etherType         : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            _drop;
            NoAction;
        }
        default_action = NoAction();
        counters = l2_fwd_counter;
    }
    // -----------------------------------------------------------------------------------------------

    direct_counter(CounterType.packets_and_bytes) cnt_adv_funct;
    SRV6_control() srv6_control;
    VNF_DEFINITIONS
    // Example of dynamically generate code:
    // UVNF_1() uvnf_1;
    apply {
        if (stdmeta.ingress_port == CPU_PORT) {
            // Packet received from CPU_PORT, this is a packet-out sent by the
            // controller. Skip table processing, set the egress port as
            // requested by the controller (packet_out header) and remove the
            // packet_out header.
            stdmeta.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        } else {
            // Other code here unrelated to SRv6 processing
            srv6_control.apply(hdr,meta, stdmeta);
            if(meta.function_to_be_executed != 0){

                // Check which VNF has to be executed. Metadata are then in users metadata
                VNF_APPLY
                // Example of dynamically generate code:
                // if (meta.function_to_be_executed == lower_SID) {
                //   uvnf_1.apply(hdr, meta, stdmeta);  
                //}
            }
            // Other code here unrelated to SRv6 processing
            if(meta.srv6_match == 0) {
                t_l2_fwd.apply();
            }
            // Update port counters at index = ingress or egress port.
            if (stdmeta.egress_spec < MAX_PORTS) {
                tx_port_counter.count((bit<32>) stdmeta.egress_spec);
            }
            if (stdmeta.ingress_port < MAX_PORTS) {
                rx_port_counter.count((bit<32>) stdmeta.ingress_port);
            }
        }
    }
}



control egress(inout headers_t hdr,
               inout metadata_t meta,
               inout standard_metadata_t stdmeta)
{
    apply { }
}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.srv6_fixedpart);
        packet.emit(hdr.srv6_seg_list);
        packet.emit(hdr.srv6_tlv_metadata);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control computeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

V1Switch(ParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;
