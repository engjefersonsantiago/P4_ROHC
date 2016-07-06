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

header_type ip_umcomp_header_t {
    fields {
        bit<160> all_fields;
      }
}

header_type udp_umcomp_header_t {
    fields {
        bit<224> all_fields;
      }
}

header_type rtp_umcomp_header_t {
    fields {
        bit<320> all_fields;
      }
}

header_type intrinsic_metadata_t {
    fields {
        bit<4> mcast_grp;
        bit<4> egress_rid;
        bit<16> mcast_hash;
        bit<32> lf_field_list;
        bit<16> recirculate_flag;
    }
}

header_type comp_header_t {
    fields {
        bit<8> id_len;	// 2:id, 6: length
        varbit<504> all_fields;
    }
    length : (id_len&0x3f)+1;
 }

header_type rohc_meta_t {
    fields {
        bit<8> decompressed_flag;
    }
}

header_type packet_options_t {
    fields {
        bit<32> payload_size;
    }
}

header ethernet_t ethernet;
header comp_header_t comp_header;
header ip_umcomp_header_t ip_umcomp_header;
header rtp_umcomp_header_t rtp_umcomp_header;

metadata intrinsic_metadata_t intrinsic_metadata;
metadata rohc_meta_t rohc_meta;
metadata packet_options_t packet_options;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    set_metadata(packet_options.payload_size, standard_metadata.packet_length - HEADER_SIZE_ETHERNET);
    return select(ethernet.etherType) {
        0xDD00    : parse_comp;
        0x7777    : parse_umcomp;
        default   : ingress;
    }
}

parser parse_comp {
   extract(comp_header);
   return ingress;  
}

parser parse_umcomp {
   extract(ip_umcomp_header);
   extract(rtp_umcomp_header);
   return ingress;  
}

action _drop() {
    drop();
}

action _nop() {
}

action set_port(in bit<9> port) {
   modify_field(standard_metadata.egress_spec, port);
}

field_list recirculate_FL {
    rohc_meta.decompressed_flag;
}

action _decompress_ip() {
    rohc_decomp_header(comp_header, ip_umcomp_header, packet_options.payload_size);    
    modify_field(rohc_meta.decompressed_flag, 1);
    modify_field(ethernet.etherType, 0x0800);
}

action _decompress_rtp() {
    rohc_decomp_header(comp_header, rtp_umcomp_header, packet_options.payload_size);    
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
    size : 128;
}

table t_ingress_ip {
    reads {
        rohc_meta.decompressed_flag : exact;
    }
    actions {
        _nop; _decompress_ip;
    }
    size : 128;
}

table t_ingress_rtp {
    reads {
        rohc_meta.decompressed_flag : exact;
    }
    actions {
        _nop; _decompress_rtp;
    }
    size : 128;
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
    size: 128;
 }

control ingress {
    apply(t_ingress_1);
    if (valid(comp_header)) {
        if (comp_header.id_len>>6 == 3) {
            apply(t_ingress_ip);
        }
        if (comp_header.id_len>>6 == 0) {
            apply(t_ingress_rtp);
        }
    }
}

control egress {
    if (valid(rtp_umcomp_header) or valid(ip_umcomp_header)) {
        apply(t_recirc);
    }
}
