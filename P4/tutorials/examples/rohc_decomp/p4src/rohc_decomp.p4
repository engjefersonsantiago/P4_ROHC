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
        bit<16> resubmit_flag;
        bit<16> modify_and_resubmit_flag;
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

header_type mymeta_t {
    fields {
        bit<8> f1;
    }
}

header_type packet_options_t {
    fields {
        bit<16> payload_size;
    }
}

header ethernet_t ethernet;
header comp_header_t comp_header;
header ip_umcomp_header_t ip_umcomp_header;
header rtp_umcomp_header_t rtp_umcomp_header;

metadata intrinsic_metadata_t intrinsic_metadata;
metadata mymeta_t mymeta;
metadata packet_options_t packet_options;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);

    return select(ethernet.etherType) {
        0xDD00 mask 0xff00 : parse_comp;
        0x7777             : parse_umcomp;
        default            : ingress;
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
   //standard_metadata.egress_spec = port;
}

field_list resubmit_FL {
    mymeta.f1;
}

action _resubmit_ip() {
    add_header(ip_umcomp_header);
    //rohc_decomp_header(comp_header, ip_umcomp_header);    
    rohc_decomp_header(comp_header, ip_umcomp_header, standard_metadata.packet_length);    
    add_header(ip_umcomp_header);
    remove_header(comp_header);   
    modify_field(mymeta.f1, 1);
    //recirculate(resubmit_FL);
    //modify_and_resubmit(resubmit_FL);
}

action _resubmit_rtp() {
    add_header(rtp_umcomp_header);
    //rohc_decomp_header(comp_header, rtp_umcomp_header);    
    rohc_decomp_header(comp_header, rtp_umcomp_header, standard_metadata.packet_length);    
    add_header(rtp_umcomp_header);
    remove_header(comp_header);   
    modify_field(mymeta.f1, 1);
    //recirculate(resubmit_FL2);
    //modify_and_resubmit(resubmit_FL2);
}


table t_ingress_1 {
    reads {
        mymeta.f1 : exact;
    }
    actions {
        _nop; set_port;
    }
    size : 128;
}

table t_ingress_ip {
    reads {
        mymeta.f1 : exact;
    }
    actions {
        _nop; _resubmit_ip;
    }
    size : 128;
}

table t_ingress_rtp {
    reads {
        mymeta.f1 : exact;
    }
    actions {
        _nop; _resubmit_rtp;
    }
    size : 128;
}

action _recirculate() {
    //modify_field(mymeta.f1, 0);
    recirculate(resubmit_FL);
}


table t_recirc {
    reads {
        mymeta.f1 : exact;
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
