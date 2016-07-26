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

header_type intrinsic_metadata_t {
    fields {
        bit<4> mcast_grp;
        bit<4> egress_rid;
        bit<16> mcast_hash;
        bit<32> lf_field_list;
        bit<16> resubmit_flag;
        bit<16> recirculate_flag;
    }
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


metadata intrinsic_metadata_t intrinsic_metadata;
metadata mymeta_t mymeta;
metadata packet_options_t packet_options;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    set_metadata(packet_options.payload_size, standard_metadata.packet_length);
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

table t_ingress_1 {
    reads {
        mymeta.f1 : exact;
    }
    actions {
        _nop; set_port;
    }
    size : 128;
}

action _recirculate() {
    modify_field(mymeta.f1, 1);
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
}

control egress {
    apply(t_recirc);
}
