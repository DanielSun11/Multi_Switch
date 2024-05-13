/* -*- P4_16 -*- */
//need to handle ARP
#include <core.p4>
#include <tna.p4>

#define PRIME 2147483647
/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
enum bit<16> ether_type_t {
    TPID       = 0x8100,
    IPV4       = 0x0800,
    ARP        = 0x0806
}

enum bit<8>  ip_proto_t {
    ICMP  = 1,
    IGMP  = 2,
    TCP   = 6,
    UDP   = 17
}
struct ports {
    bit<16>  sp;
    bit<16>  dp;
}
#define SW1_H_P1 28    //port 13/0
#define SW1_H_P2 24    //port 19/0

#define SW1_SW2_P1 12  //port 15/0
#define SW1_SW2_P2 0   //port 17/0

#define SW2_SW1_P1 4   //port 16/0
#define SW2_SW1_P2 8   //port 18/0

#define SW2_H_P1 20    //port 14/0
#define SW2_H_P2 16    //port 20/0


type bit<48> mac_addr_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    ether_type_t  ether_type;
}

header vlan_tag_h {
    bit<3>        pcp;
    bit<1>        cfi;
    bit<12>       vid;
    ether_type_t  ether_type;
}

header arp_h {
    bit<16>       htype;
    bit<16>       ptype;
    bit<8>        hlen;
    bit<8>        plen;
    bit<16>       opcode;
    mac_addr_t    hw_src_addr;
    bit<32>       proto_src_addr;
    mac_addr_t    hw_dst_addr;
    bit<32>       proto_dst_addr;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<7>       diffserv;
    bit<1>       res;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>   protocol;
    bit<16>      hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header icmp_h {
    bit<16>  type_code;
    bit<16>  checksum;
}

header igmp_h {
    bit<16>  type_code;
    bit<16>  checksum;
}

header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t{
    ethernet_h         ethernet;
    arp_h              arp;
    vlan_tag_h[2]      vlan_tag;
    ipv4_h             ipv4;
    icmp_h             icmp;
    igmp_h             igmp;
    tcp_h              tcp;
    udp_h              udp;
}


    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/


struct my_ingress_metadata_t {
    bit<32> ll;
    bit<16> ecmp_select;

}

    /***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
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
        transition meta_init;
    }

    state meta_init {

        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        /* 
         * The explicit cast allows us to use ternary matching on
         * serializable enum
         */        
        transition select((bit<16>)hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parse_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parse_ipv4;
            (bit<16>)ether_type_t.ARP             :  parse_arp;
            default :  accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ether_type_t.TPID :  parse_vlan_tag;
            ether_type_t.IPV4 :  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            1 : parse_icmp;
            2 : parse_igmp;
            6 : parse_tcp;
           17 : parse_udp;
            default : accept;
        }
    }


    state parse_icmp {
       meta.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.icmp);
        transition accept;
    }
    
    state parse_igmp {
      meta.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.igmp);
        transition accept;
    }
    
    state parse_tcp {
        meta.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.tcp);
        transition accept;
    }
    
    state parse_udp {
        meta.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.udp);
        transition accept;
    }


}
//calculate hash code
control Ecmp_hashcode(    
    in my_ingress_headers_t                          hdr,
    out my_ingress_metadata_t                        meta,
    in bit<16>                                       ecmp_count
    )
{
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_udp;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_tcp;
    bit<16> hashcode = 0;

    apply{
        if(hdr.ipv4.isValid()){
            if(hdr.udp.isValid()){
                hashcode = hash_udp.get(
                        { hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr,
                        hdr.ipv4.protocol,
                        hdr.udp.src_port,
                        hdr.udp.dst_port }
                );
            }else if(hdr.tcp.isValid()){
                hashcode = hash_tcp.get(
                        { hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr,
                        hdr.ipv4.protocol,
                        hdr.tcp.src_port,
                        hdr.tcp.dst_port }
                );
            }
        }
        meta.ecmp_select = hashcode%ecmp_count;
    }
}
control Ingress(/* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    bit<16>hashcode = 0;
    bit<16>ecmp_count = 2;


	action send(PortId_t port) {
		ig_tm_md.ucast_egress_port = port;
	}
    @hidden action switch1_from_switch () {
        // no statements here, by design
    }
    @hidden action switch1_from_server () {
        // no statements here, by design
    }
    @hidden action switch2_from_switch () {
        // no statements here, by design
    }
    @hidden action switch2_from_server () {
        // no statements here, by design
    }
    @hidden action switch_default () {
        // no statements here, by design
    }

    @hidden table select_ingress_port {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            switch1_from_switch;
            switch1_from_server;
            switch2_from_switch;
            switch2_from_server;
            switch_default;
        }
        const entries = {
            //swtich2->switch1
            SW1_SW2_P2   :   switch1_from_switch;    //SW1_SW2_P2
            SW1_SW2_P1   :   switch1_from_switch;     //SW1_SW2_P1
            //server->switch1
            SW1_H_P1  :    switch1_from_server;       //SW1_H_P1
            SW1_H_P2  :   switch1_from_server;       //SW1_H_P2
            //switch1->switch2
            SW2_SW1_P1   :   switch2_from_switch;    //SW2_SW1_P1
            SW2_SW1_P2   :   switch2_from_switch;    //SW2_SW1_P2
            //server->switch2
            SW2_H_P1  :    switch2_from_server;       //SW2_H_P1
            SW2_H_P2  :   switch2_from_server;       //SW2_H_P2
        }
        const default_action = switch_default;
    }


	table switch1_from_switch_table {
		key = { hdr.ethernet.ether_type : exact;
                hdr.ipv4.dst_addr : ternary;}
		actions = { send;}
        size = 8;
        const entries = {
            ((bit<16>)ether_type_t.IPV4,0x0e0e0e00 &&& 0xffffff00) : send(SW1_H_P2); //14.14.14.x -> SW1_H_P2 19/0 24
            ((bit<16>)ether_type_t.IPV4,0x0d0d0d00 &&& 0xffffff00) : send(SW1_H_P1); //13.13.13.x -> SW1_H_P1 13/0 28
        }
	}
    table switch1_from_server_table {
		key = { meta.ecmp_select : exact;}
		actions = { send;}
        const entries = {
            0:send(SW1_SW2_P1);
            1:send(SW1_SW2_P2);
        }
	}
    table switch2_from_switch_table {
		key = { hdr.ethernet.ether_type : exact;
                hdr.ipv4.dst_addr : ternary;}
		actions = { send;}
        size = 8;
        const entries = {
            ((bit<16>)ether_type_t.IPV4,0x0e0e0e00 &&& 0xffffff00) : send(SW2_H_P2); //14.14.14.x ->SW2_H_P2 20/0 16
            ((bit<16>)ether_type_t.IPV4,0x0d0d0d00 &&& 0xffffff00) : send(SW2_H_P1); //13.13.13.x ->SW2_H_P1 14/0 20
        }
	}
    table switch2_from_server_table {
		key = { meta.ecmp_select : exact;}
		actions = { send;}
        const entries = {
            0:send(SW2_SW1_P1);
            1:send(SW2_SW1_P2);
        }
	}
    table switch1_arp_table {
		key = { hdr.ethernet.ether_type : exact;
                hdr.arp.proto_dst_addr  : ternary;}
		actions = { send;}
        size = 8;
        const entries = {
            ((bit<16>)ether_type_t.ARP , 0x0e0e0e00 &&& 0xffffff00) : send(SW1_H_P2); //14.14.14.x -> SW1_H_P2 19/0 24
            ((bit<16>)ether_type_t.ARP , 0x0d0d0d00 &&& 0xffffff00) : send(SW1_H_P1); //13.13.13.x -> SW1_H_P1 13/0 28
        }
	}
    table switch2_arp_table {
		key = { hdr.ethernet.ether_type : exact;
                hdr.arp.proto_dst_addr  : ternary;}
		actions = { send;}
        size = 8;
        const entries = {
            ((bit<16>)ether_type_t.ARP , 0x0e0e0e00 &&& 0xffffff00) : send(SW2_H_P2); //14.14.14.x -> SW2_H_P2 20/0 16
            ((bit<16>)ether_type_t.ARP , 0x0d0d0d00 &&& 0xffffff00) : send(SW2_H_P1); //13.13.13.x -> SW2_H_P1 14/0 20
        }
	}
    // table send_t {
	// 	key = { ig_intr_md.ingress_port: exact;}
	// 	actions = { send;}
    //     const entries = {
    //         128:send(136);
    //         136:send(128);
    //     }
	// }
    Ecmp_hashcode() hash;
apply {

    switch (select_ingress_port.apply().action_run) {
        switch1_from_switch: {
            switch1_arp_table.apply();
            switch1_from_switch_table.apply(); 
        }
        switch1_from_server: {
            hash.apply(hdr,meta,ecmp_count);
            switch1_from_server_table.apply(); 
        }
        switch2_from_switch: {
            switch2_arp_table.apply();
            switch2_from_switch_table.apply(); 
        }
        switch2_from_server: {
            hash.apply(hdr,meta,ecmp_count);
            switch2_from_server_table.apply(); 
        }
    }
	//send_t.apply();
}
}
// control Ingress1(/* User */
//     inout my_ingress_headers_t                       hdr,
//     inout my_ingress_metadata_t                      meta,
//     /* Intrinsic */
//     in    ingress_intrinsic_metadata_t               ig_intr_md,
//     in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
//     inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
//     inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
// {
//     bit<16>hashcode = 0;
//     bit<16>ecmp_count = 2;

//     //Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_udp;
//     //Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_tcp;

// 	action send(PortId_t port) {
// 		ig_tm_md.ucast_egress_port = port;
// 	}
//     @hidden action switch1_from_switch () {
//         // no statements here, by design
//     }
//     @hidden action switch1_from_server () {
//         // no statements here, by design
//     }
//     @hidden action switch2_from_switch () {
//         // no statements here, by design
//     }
//     @hidden action switch2_from_server () {
//         // no statements here, by design
//     }
//     @hidden action switch_default () {
//         // no statements here, by design
//     }

//     @hidden table select_ingress_port {
//         key = {
//             ig_intr_md.ingress_port : exact;
//         }
//         actions = {
//             switch1_from_switch;
//             switch1_from_server;
//             switch2_from_switch;
//             switch2_from_server;
//             switch_default;
//         }
//         const entries = {
//             //swtich2->switch1
//             0   :   switch1_from_switch;    //port 17/0
//             12  :   switch1_from_switch;    //port 15/0
//             //server->switch1
//             28 :   switch1_from_server;    //port 1/0
//             24  :   switch1_from_server;    //port 19/0
//             //switch1->switch2
//             4   :   switch2_from_switch;    //port 16/0
//             8   :   switch2_from_switch;    //port 18/0
//             //server->switch2
//             20 :   switch2_from_server;    //port 2/0 
//             16  :   switch2_from_server;    //port 20/0 
//         }
//         const default_action = switch_default;
//     }


// 	table switch1_from_switch_table {
// 		key = { hdr.ipv4.dst_addr : ternary;}
// 		actions = { send;}
//         size = 8;
//         const entries = {
//             0x0e0e0e00 &&& 0xffffff00 : send(24); //14.14.14.x -> 19/0 24
//             0x0d0d0d00 &&& 0xffffff00 : send(28);//13.13.13.x -> 1/0 28
//         }
// 	}
//     table switch1_from_server_table {
// 		key = { meta.ecmp_select : exact;}
// 		actions = { send;}
//         const entries = {
//             0:send(12);
//             1:send(0);
//         }
// 	}
//     table switch2_from_switch_table {
// 		key = { hdr.ipv4.dst_addr : ternary;}
// 		actions = { send;}
//         size = 8;
//         const entries = {
//             0x0e0e0e00 &&& 0xffffff00 : send(16); //14.14.14.x -> 20/0 16
//             0x0d0d0d00 &&& 0xffffff00 : send(20);//13.13.13.x -> 14/0 20
//         }
// 	}
//     table switch2_from_server_table {
// 		key = { meta.ecmp_select : exact;}
// 		actions = { send;}
//         const entries = {
//             0:send(4);
//             1:send(8);
//         }
// 	}
//     table switch1_arp_table {
// 		key = { hdr.ethernet.ether_type : exact;
//                 hdr.arp.proto_dst_addr  : ternary;}
// 		actions = { send;}
//         size = 8;
//         const entries = {
//             ((bit<16>)ether_type_t.ARP , 0x0e0e0e00 &&& 0xffffff00) : send(24); //14.14.14.x -> 20/0 16
//             ((bit<16>)ether_type_t.ARP , 0x0d0d0d00 &&& 0xffffff00) : send(28);//13.13.13.x -> 13/0 28
//         }
// 	}
//     table switch2_arp_table {
// 		key = { hdr.ethernet.ether_type : exact;
//                 hdr.arp.proto_dst_addr  : ternary;}
// 		actions = { send;}
//         size = 8;
//         const entries = {
//             ((bit<16>)ether_type_t.ARP , 0x0e0e0e00 &&& 0xffffff00) : send(16); //14.14.14.x -> 20/0 16
//             ((bit<16>)ether_type_t.ARP , 0x0d0d0d00 &&& 0xffffff00) : send(20);//13.13.13.x -> 14/0 20
//         }
// 	}
//     // table send_t {
// 	// 	key = { ig_intr_md.ingress_port: exact;}
// 	// 	actions = { send;}
//     //     const entries = {
//     //         128:send(136);
//     //         136:send(128);
//     //     }
// 	// }
//     Ecmp_hashcode() hash;
// apply {

//     switch (select_ingress_port.apply().action_run) {
//         switch1_from_switch: {
//             switch1_arp_table.apply();
//             switch1_from_switch_table.apply(); 
//         }
//         switch1_from_server: {
//             hash.apply(hdr,meta,ecmp_count);
//             switch1_from_server_table.apply(); 
//         }
//         switch2_from_switch: {
//             switch2_arp_table.apply();
//             switch2_from_switch_table.apply(); 
//         }
//         switch2_from_server: {
//             hash.apply(hdr,meta,ecmp_count);
//             switch2_from_server_table.apply(); 
//         }
//     }
// 	//send_t.apply();
// }
// }



control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
        // Checksum() ipv4_checksum;
    
    
     Checksum() ipv4_checksum;
    
    apply {
        // if (hdr.ipv4.isValid()) {
        //     hdr.ipv4.hdr_checksum = ipv4_checksum.update({
        //         hdr.ipv4.version,
        //         hdr.ipv4.ihl,
        //         hdr.ipv4.diffserv,
        //         hdr.ipv4.res,
        //         hdr.ipv4.total_len,
        //         hdr.ipv4.identification,
        //         hdr.ipv4.flags,
        //         hdr.ipv4.frag_offset,
        //         hdr.ipv4.ttl,
        //         hdr.ipv4.protocol,
        //         hdr.ipv4.src_addr,
        //         hdr.ipv4.dst_addr
        //     });  
        //}
        pkt.emit(hdr);
        
    }
}
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/


    struct my_egress_headers_t {
    ethernet_h         ethernet;
vlan_tag_h[2]      vlan_tag;
    ipv4_h             ipv4;
}



    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {

}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    

    apply {
      
}
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{

    apply {
          pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe1;

Switch(pipe) main;