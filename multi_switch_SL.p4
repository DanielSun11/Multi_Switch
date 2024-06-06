/* -*- P4_16 -*- */
//need to handle ARP
#include <core.p4>
#include <tna.p4>
#include "macros.p4"
#include "headers.p4"

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
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
    //
    // CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
    //                        true,          // reversed
    //                        false,         // use msb?
    //                        false,         // extended?
    //                        32w0xFFFFFFFF, // initial shift register value
    //                        32w0xFFFFFFFF  // result xor
    //                        ) poly;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_udp;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_tcp;
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
                meta.ecmp_select = hdr.udp.src_port % ecmp_count;
            }else if(hdr.tcp.isValid()){
                hashcode = hash_tcp.get(
                        { hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr,
                        hdr.ipv4.protocol,
                        hdr.tcp.src_port,
                        hdr.tcp.dst_port }
                );
                meta.ecmp_select = hdr.tcp.src_port % ecmp_count;
            }
        }
        //meta.ecmp_select = hashcode%ecmp_count;
         
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
    @hidden action switch3_from_switch () {
        // no statements here, by design
    }
    @hidden action switch4_from_switch () {
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
            switch3_from_switch;
            switch4_from_switch;
            switch_default;
        }
        const entries = {
            //swtich3/4<->switch1
            SW1_SW4_P1   :   switch1_from_switch;    //SW1_SW4_P1
            SW1_SW3_P1   :   switch1_from_switch;    //SW1_SW3_P1
            //server<->switch1
            SW1_H_P1     :   switch1_from_server;    //SW1_H_P1
            SW1_H_P2     :   switch1_from_server;    //SW1_H_P2
            //swtich3/4<->switch2
            SW2_SW3_P1   :   switch2_from_switch;    //SW2_SW3_P1
            SW2_SW4_P1   :   switch2_from_switch;    //SW2_SW4_P1
            //server<->switch2
            SW2_H_P1     :   switch2_from_server;     //SW2_H_P1
            SW2_H_P2     :   switch2_from_server;     //SW2_H_P2
            //switch1/2<->switch3
            SW3_SW1_P1   :   switch3_from_switch;
            SW3_SW2_P1   :   switch3_from_switch;
            //switch1/2<->switch4
            SW4_SW1_P1   :   switch4_from_switch;
            SW4_SW2_P1   :   switch4_from_switch;

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
            0:send(SW1_SW3_P1);
            1:send(SW1_SW4_P1);
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
            0:send(SW2_SW3_P1);
            1:send(SW2_SW4_P1);
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
    table switch3_from_switch_table {
		key = {
            ig_intr_md.ingress_port : exact;
        }
		actions = {send;}
        size = 8;
        const entries = {
            SW3_SW1_P1 : send(SW3_SW2_P1); // from sw1 to sw2
            SW3_SW2_P1 : send(SW3_SW1_P1); // from sw2 to sw1
        }
	}
    table switch4_from_switch_table {
		key = {
            ig_intr_md.ingress_port : exact;
        }
		actions = {send;}
        size = 8;
        const entries = {
            SW4_SW1_P1 : send(SW4_SW2_P1); // from sw1 to sw2
            SW4_SW2_P1 : send(SW4_SW1_P1); // from sw2 to sw1
        }
	}
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
        switch3_from_switch: {
            switch3_from_switch_table.apply();
        }
        switch4_from_switch: {
            switch4_from_switch_table.apply();
        }
    }
}
}

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
     Checksum() ipv4_checksum;
    
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });  
        }
        pkt.emit(hdr);
        
    }
}
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

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
        transition meta_init;
    }
    state meta_init {
        transition parse_ethernet;
    }
    state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type){
			(bit<16>) ether_type_t.IPV4: parse_ipv4;
			(bit<16>) ether_type_t.ARP: parse_arp;
			default: accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			(bit<8>) ip_proto_t.TCP: parse_tcp;
			(bit<8>) ip_proto_t.UDP: parse_udp;
            (bit<8>) ip_proto_t.ICMP: parse_icmp;
		    default: accept;
		}
	}

	state parse_arp {
		pkt.extract(hdr.arp);
		transition accept;
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		transition accept;
	}

	state parse_udp {
		pkt.extract(hdr.udp);
        transition accept;
	}
    state parse_icmp {
        pkt.extract(hdr.icmp);
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
    //using register store the ECN threshold
    Register<bit<32>,bit<1>>(1,2500) reg_ecn_marking_threshold; // default = 1250 (100KB)
	RegisterAction<bit<32>,bit<1>,bit<1>>(reg_ecn_marking_threshold) cmp_ecn_marking_threshold = {
		void apply(inout bit<32> reg_val, out bit<1> rv){
			if((bit<32>)eg_intr_md.deq_qdepth >= reg_val){
				rv = 1;
			}
			else {
				rv = 0;
			}
		}
	};
    // for debugging ECN marking
    Register<bit<32>,bit<1>>(1,2) reg_ecn_marking_cntr;
    RegisterAction<bit<32>,bit<1>,bit<1>>(reg_ecn_marking_cntr) incr_ecn_marking_cntr = {
		void apply(inout bit<32> reg_val, out bit<1> rv){
			reg_val = reg_val + 1;
		}
	};
    action dctcp_check_ecn_marking(){
		meta.exceeded_ecn_marking_threshold = cmp_ecn_marking_threshold.execute(0);
	}
    action mark_ecn_ce_codepoint(){
		hdr.ipv4.ecn = 0b11;
	}
    apply {
        if(hdr.ipv4.ecn == 0b01 || hdr.ipv4.ecn == 0b10){
            dctcp_check_ecn_marking();
            if(meta.exceeded_ecn_marking_threshold == 1){
                mark_ecn_ce_codepoint();
                incr_ecn_marking_cntr.execute(0);
            }
        }
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
    
    Checksum() ipv4_checksum;
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });  
        }
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

Switch(pipe) main;