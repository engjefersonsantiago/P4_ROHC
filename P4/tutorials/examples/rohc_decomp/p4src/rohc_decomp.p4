/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define HEADER_SIZE_ETHERNET 14

header_type ethernet_t {
    fields {
        bit<48> dstAddr;
        bit<48> srcAddr;
        bit<16> etherType;
    }
}

// Field are multiple of byte to easy the data manipulation
// IP header
header_type ipv4_t {
    fields {
        bit<8>  version_ihl;      // [7..4] version, [3..0] ihl
        bit<8>  diffserv;
        bit<16> totalLen;
        bit<16> identification;
        bit<16> flags_fragOffset; // [15..13] flags, fragOffset [12..0]
        bit<8>  ttl;
        bit<8>  protocol;
        bit<16> hdrChecksum;
        bit<32> srcAddr;
        bit<32> dstAddr;
    }
}

// UDP header
header_type udp_t {
	  fields {
	  	  bit<16> srcPort;
	  	  bit<16> dstPort;
	  	  bit<16> hdrLength;
	  	  bit<16> chksum;
    }
}

// RTP header
header_type rtp_t {
	  fields {
		    bit<8>      version_pad_ext_nCRSC; // [7..6] version, [5] pad, [4] ext, [3..0] nCRSC
		    bit<8>      marker_payloadType;    // [7] marker, [6..0] payloadType
		    bit<16>     sequenceNumber;
		    bit<32>     timestamp;
		    bit<32>     SSRC;
    }
}

header_type ip_uncomp_header_t {
    fields {
        bit<160> all_fields;
      }
}

header_type udp_uncomp_header_t {
    fields {
        bit<224> all_fields;
      }
}

header_type rtp_uncomp_header_t {
    fields {
        bit<320> all_fields;
      }
}

// IP header
header_type rtp_all_headers_t {
    fields {
        bit<8>  version_ihl;      // [7..4] version, [3..0] ihl
        bit<8>  diffserv;
        bit<16> totalLen;
        bit<16> identification;
        bit<16> flags_fragOffset; // [15..13] flags, fragOffset [12..0]
        bit<8>  ttl;
        bit<8>  protocol;
        bit<16> hdrChecksum;
        bit<32> srcAddr;
        bit<32> dstAddr;
 	  	  bit<16> srcPort;
	  	  bit<16> dstPort;
	  	  bit<16> hdrLength;
	  	  bit<16> chksum;
		    bit<8>  version_pad_ext_nCRSC; // [7..6] version, [5] pad, [4] ext, [3..0] nCRSC
		    bit<8>  marker_payloadType;    // [7] marker, [6..0] payloadType
		    bit<16> sequenceNumber;
		    bit<32> timestamp;
		    bit<32> SSRC;
    }
}


header_type intrinsic_metadata_t {
    fields {
        bit<4>    mcast_grp;
        bit<4>    egress_rid;
        bit<16>   mcast_hash;
        bit<32>   lf_field_list;
        bit<16>   recirculate_flag;
    }
}

header_type comp_header_t {
    fields {
        bit<8>        id;
        bit<8>        len;
        varbit<2032>  all_fields;
    }
    length : len + 2;
 }

header_type rohc_meta_t {
    fields {
        bit<1>  decompressed_flag;
        bit<1>  compressed_flag;
    }
}

header_type packet_options_t {
    fields {
        bit<32> payload_size;
    }
}

header ethernet_t ethernet;
header ipv4_t ipv4;
header udp_t udp;
header rtp_t rtp;
header comp_header_t comp_header;
header ip_uncomp_header_t ip_uncomp_header;
header udp_uncomp_header_t udp_uncomp_header;
header rtp_uncomp_header_t rtp_uncomp_header;

metadata intrinsic_metadata_t intrinsic_metadata;
metadata rohc_meta_t rohc_meta;
metadata packet_options_t packet_options;
metadata rtp_all_headers_t rtp_all_headers_meta;


parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    set_metadata(packet_options.payload_size, standard_metadata.packet_length - HEADER_SIZE_ETHERNET);
    return select(ethernet.etherType) {
        0x0800    : parse_ipv4;
        0xDD00    : parse_comp;
        0x7777    : parse_uncomp;
        default   : ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol){
        0x11      : parse_udp; 
        default   : ingress;  
    }
}

parser parse_udp {
    extract(udp);
    return select(udp.dstPort){
        1234      : parse_rtp; 
        1235      : parse_rtp; 
        5004      : parse_rtp; 
        5005      : parse_rtp; 
        default   : ingress;  
    }
}

parser parse_rtp {
    extract(rtp);
    return ingress;  
}

parser parse_comp {
    //extract(comp_header);
    return ingress;  
}


parser parse_uncomp {
    extract(ip_uncomp_header);
    extract(rtp_uncomp_header);
    return ingress;  
}

action _drop() {
    drop();
}

action _nop() {
}

action set_port(in bit<9> port) {
   	modify_field(standard_metadata.egress_spec, port);
   	modify_field(rohc_meta.decompressed_flag, 0);
}

field_list recirculate_FL {
    rohc_meta.decompressed_flag;
}

action _decompress_ip() {
    rohc_decomp_header();    
    modify_field(rohc_meta.decompressed_flag, 1);
    modify_field(ethernet.etherType, 0x0800);
}

action _decompress_udp() {
    rohc_decomp_header();    
    modify_field(rohc_meta.decompressed_flag, 1);
    modify_field(ethernet.etherType, 0x0800);
}

action _decompress_rtp() {
    rohc_decomp_header();  
		rohc_meta.decompressed_flag = 1;  
    modify_field(rohc_meta.decompressed_flag, 1);
    modify_field(ethernet.etherType, 0x0800);
}

table t_ingress_1 {
    reads {
        rohc_meta.decompressed_flag : exact;
    }
    actions {
        _nop; set_port;
    }
    size : 2;
}

table t_ingress_ip {
    reads {
        rohc_meta.decompressed_flag : exact;
    }
    actions {
        _nop; _decompress_ip;
    }
    size : 2;
}

table t_ingress_udp {
    reads {
        rohc_meta.decompressed_flag : exact;
    }
    actions {
        _nop; _decompress_udp;
    }
    size : 2;
}

table t_ingress_rtp {
    reads {
        rohc_meta.decompressed_flag : exact;
    }
    actions {
        _nop; _decompress_rtp;
    }
    size : 2;
}

action _recirculate() {
    recirculate(recirculate_FL);
}

table t_recirc {
    reads {
        rohc_meta.decompressed_flag : exact;
    }
    actions {
        _nop; _recirculate;
    }
    size: 2;
}

field_list ipv4_checksum_list {
    ipv4.version_ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags_fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm     : csum16;
    output_width  : 16;
}

action _compress () {
    modify_field(rtp_all_headers_meta.version_ihl           , ipv4.version_ihl);
    modify_field(rtp_all_headers_meta.diffserv              , ipv4.diffserv);
    modify_field(rtp_all_headers_meta.totalLen              , ipv4.totalLen);
    modify_field(rtp_all_headers_meta.identification        , ipv4.identification);
    modify_field(rtp_all_headers_meta.flags_fragOffset      , ipv4.flags_fragOffset);
    modify_field(rtp_all_headers_meta.ttl                   , ipv4.ttl);
    modify_field(rtp_all_headers_meta.protocol              , ipv4.protocol);
    modify_field(rtp_all_headers_meta.hdrChecksum           , ipv4.hdrChecksum);
    modify_field(rtp_all_headers_meta.srcAddr               , ipv4.srcAddr);
    modify_field(rtp_all_headers_meta.dstAddr               , ipv4.dstAddr);
 	  modify_field(rtp_all_headers_meta.srcPort               , udp.srcPort);
	  modify_field(rtp_all_headers_meta.dstPort               , udp.dstPort);
	  modify_field(rtp_all_headers_meta.hdrLength             , udp.hdrLength);
	  modify_field(rtp_all_headers_meta.chksum                , udp.chksum);
		modify_field(rtp_all_headers_meta.version_pad_ext_nCRSC , rtp.version_pad_ext_nCRSC);
		modify_field(rtp_all_headers_meta.marker_payloadType    , rtp.marker_payloadType);
		modify_field(rtp_all_headers_meta.sequenceNumber        , rtp.sequenceNumber);
		modify_field(rtp_all_headers_meta.timestamp             , rtp.timestamp);
		modify_field(rtp_all_headers_meta.SSRC                  , rtp.SSRC);
    rohc_comp_header(rtp_all_headers_meta, packet_options.payload_size);   
	  remove_header(rtp);
	  remove_header(ipv4);
	  remove_header(udp);
	  modify_field(ethernet.etherType, 0xDD00);
}

table t_compress {
   reads {
        rohc_meta.decompressed_flag : exact;
    }
    actions { 
        _nop; _compress;
    }
    size : 1;
}
 
control ingress {
    apply(t_ingress_1);
		if(ethernet.etherType == 0xDD00) 
	   	apply(t_ingress_rtp);
}

control egress {
    //if (rohc_meta.decompressed_flag == 1) {
        apply(t_recirc);
    //} table_add t_compress _compress 0 =>
    apply(t_compress);
}
