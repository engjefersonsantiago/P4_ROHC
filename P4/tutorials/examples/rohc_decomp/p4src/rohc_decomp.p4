/*
 * Jeferson Santiago da Silva 
 * Laurent Olivier Chiquette (l.o.chiquette@gmail.com)
 */

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

header_type intrinsic_metadata_t {
    fields {
        bit<4>    mcast_grp;
        bit<4>    egress_rid;
        bit<16>   mcast_hash;
        bit<32>   lf_field_list;
        bit<16>   resubmit_flag;
        bit<16>   modify_and_resubmit_flag;
    }
}

header ethernet_t ethernet;
header ipv4_t ipv4;
header udp_t udp;
header rtp_t rtp;

metadata intrinsic_metadata_t intrinsic_metadata;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(ethernet.etherType) {
        0x0800    : parse_ipv4;
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

extern_type ExternRohcCompressor {
        
    attribute verbose {
        /* Must be either:
            quiet
            debug_mode
        */
        type: string;
    }

    method rohc_comp_header ();
}

extern ExternRohcCompressor my_rohc_comp {
  verbose: 0x01;
}

extern_type ExternRohcDecompressor {
        
    attribute verbose {
        /* Must be either:
            quiet
            debug_mode
        */
        type: string;
    }

    method rohc_decomp_header ();
}

extern ExternRohcDecompressor my_rohc_decomp {
  verbose: 0x01;
}


action _drop() {
    drop();
}

action _nop() {
}

action set_port(in bit<9> port) {
    modify_field(standard_metadata.egress_spec, port);
    intrinsic_metadata.modify_and_resubmit_flag = 0; 
}

field_list resubmit_FL {
    intrinsic_metadata.modify_and_resubmit_flag;
}

action _resubmit() {
    modify_and_resubmit(resubmit_FL);
}

action _decompress() {
    ethernet.etherType = 0x0800;
    my_rohc_decomp.rohc_decomp_header();  
    intrinsic_metadata.modify_and_resubmit_flag = 1;  
}

action _compress () {
    //ipv4.ttl = ipv4.ttl - 1;
    my_rohc_comp.rohc_comp_header();
    modify_field(ethernet.etherType, 0xDD00);
}

table t_ingress_1 {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        _nop; set_port;
    }
    size : 2;
}

table t_ingress_rohc_decomp {
    reads {
        ethernet.etherType : exact;
    }
    actions {
        _nop; _decompress;
    }
    size : 2;
}

table t_resub {
    reads {
        intrinsic_metadata.modify_and_resubmit_flag : exact;
    }
    actions {
        _nop; _resubmit;
    }
    size: 2;
}


table t_compress {
   reads {
        standard_metadata.egress_port : exact;
    }
    actions { 
        _nop; _compress;
    }
    size : 1;
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

calculated_field ipv4.hdrChecksum  {
    //verify ipv4_checksum;
    update ipv4_checksum;
}
 
control ingress {
    apply(t_ingress_1);
    apply(t_ingress_rohc_decomp);
    if(intrinsic_metadata.modify_and_resubmit_flag == 1)			
	      apply(t_resub);
}

control egress {
    if(intrinsic_metadata.modify_and_resubmit_flag != 1)
        apply(t_compress);
}
