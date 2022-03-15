if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14788" );
	script_version( "$Revision: 10411 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IP protocols scan" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "global_settings.sc" );
	script_exclude_keys( "keys/islocalhost", "keys/TARGET_IS_IPV6" );
	script_timeout( 900 );
	script_add_preference( name: "Run IP protocols scan", type: "checkbox", value: "no" );
	script_xref( name: "URL", value: "http://www.iana.org/assignments/protocol-numbers" );
	script_tag( name: "summary", value: "This plugin detects the protocols understood by the remote IP stack. The routine
  might take good amount of time to complete so it is not enabled by default." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("global_settings.inc.sc");
run_nvt = script_get_preference( "Run IP protocols scan" );
if(!ContainsString( run_nvt, "yes" )){
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
if(islocalhost()){
	exit( 0 );
}
s = this_host();
d = get_host_ip();
f = "icmp and src " + d + " and dst " + s + " and icmp[0]=3 and icmp[1]=2";
reject_nb = 0;
if(debug_level){
	start_time = unixtime();
}
func test_proto( proto, timeout ){
	var ip, id, j, hl, r, icmp, orig, pr;
	id = rand() & 0xFFFF;
	ip = forge_ip_packet( ip_v: 4, ip_hl: 5, ip_tos: 0, ip_p: proto, ip_id: id, ip_ttl: 64, ip_off: 0, ip_src: s, ip_dst: d, ip_len: 20 );
	for(j = 0;j < 3;j++){
		r = send_packet( packet: ip, pcap_active: TRUE, pcap_filter: f, pcap_timeout: timeout );
		if(isnull( r )){
			return 0;
		}
		hl = ord( r[0] ) & 0xF;
		hl *= 4;
		icmp = substr( r, hl );
		orig = substr( icmp, 8 );
		pr = ord( orig[9] );
		if( pr == proto ) {
			return 1;
		}
		else {
			if(debug_level){
				display( "ip_protocol_scan(", d, "): ", "\\tpr=", pr, "\\tproto=", proto, "\\n" );
			}
		}
	}
	return 0;
}
tictac = 1;
old_reject_nb = -1;
reject_nb = 0;
for(j = 0;old_reject_nb != reject_nb;j++){
	old_reject_nb = reject_nb;
	for(p = 255;p >= 0;p--){
		if(!rejected[p]){
			if(test_proto( proto: p, timeout: tictac + j )){
				rejected[p] = 1;
				reject_nb++;
				if(debug_level > 1){
					display( "ip_protocol_scan(", d, "): ", p, " rejected - pass # ", j, "\n" );
				}
			}
		}
		if(reject_nb == 0){
			if(p < 240){
				if(debug_level){
					display( "ip_protocol_scan(", d, "): no answer on 16 first protocols. Exiting\\n" );
				}
				exit( 0 );
			}
		}
	}
	if(debug_level){
		display( "ip_protocol_scan(", d, "): reject_nb=", reject_nb, "\\tj=", j, "\\n" );
	}
}
if(reject_nb == 0){
	exit( 0 );
}
report = "The following IP protocols are accepted on this host:\n";
name[0] = "HOPOPT";
name[1] = "ICMP";
name[2] = "IGMP";
name[3] = "GGP";
name[4] = "IP";
name[5] = "ST";
name[6] = "TCP";
name[7] = "CBT";
name[8] = "EGP";
name[9] = "IGP";
name[10] = "BBN-RCC-MON";
name[11] = "NVP-II";
name[12] = "PUP";
name[13] = "ARGUS";
name[14] = "EMCON";
name[15] = "XNET";
name[16] = "CHAOS";
name[17] = "UDP";
name[18] = "MUX";
name[19] = "DCN-MEAS";
name[20] = "HMP";
name[21] = "PRM";
name[22] = "XNS-IDP";
name[23] = "TRUNK-1";
name[24] = "TRUNK-2";
name[25] = "LEAF-1";
name[26] = "LEAF-2";
name[27] = "RDP";
name[28] = "IRTP";
name[29] = "ISO-TP4";
name[30] = "NETBLT";
name[31] = "MFE-NSP";
name[32] = "MERIT-INP";
name[33] = "SEP";
name[34] = "3PC";
name[35] = "IDPR";
name[36] = "XTP";
name[37] = "DDP";
name[38] = "IDPR-CMTP";
name[39] = "TP++";
name[40] = "IL";
name[41] = "IPv6";
name[42] = "SDRP";
name[43] = "IPv6-Route";
name[44] = "IPv6-Frag";
name[45] = "IDRP";
name[46] = "RSVP";
name[47] = "GRE";
name[48] = "MHRP";
name[49] = "BNA";
name[50] = "ESP";
name[51] = "AH";
name[52] = "I-NLSP";
name[53] = "SWIPE";
name[54] = "NARP";
name[55] = "MOBILE";
name[56] = "TLSP";
name[57] = "SKIP";
name[58] = "IPv6-ICMP";
name[59] = "IPv6-NoNxt";
name[60] = "IPv6-Opts";
name[62] = "CFTP";
name[64] = "SAT-EXPAK";
name[65] = "KRYPTOLAN";
name[66] = "RVD";
name[67] = "IPPC";
name[69] = "SAT-MON";
name[70] = "VISA";
name[71] = "IPCV";
name[72] = "CPNX";
name[73] = "CPHB";
name[74] = "WSN";
name[75] = "PVP";
name[76] = "BR-SAT-MON";
name[77] = "SUN-ND";
name[78] = "WB-MON";
name[79] = "WB-EXPAK";
name[80] = "ISO-IP";
name[81] = "VMTP";
name[82] = "SECURE-VMTP";
name[83] = "VINES";
name[84] = "TTP";
name[85] = "NSFNET-IGP";
name[86] = "DGP";
name[87] = "TCF";
name[88] = "EIGRP";
name[89] = "OSPFIGP";
name[90] = "Sprite-RPC";
name[91] = "LARP";
name[92] = "MTP";
name[93] = "AX.25";
name[94] = "IPIP";
name[95] = "MICP";
name[96] = "SCC-SP";
name[97] = "ETHERIP";
name[98] = "ENCAP";
name[100] = "GMTP";
name[101] = "IFMP";
name[102] = "PNNI";
name[103] = "PIM";
name[104] = "ARIS";
name[105] = "SCPS";
name[106] = "QNX";
name[107] = "A/N";
name[108] = "IPComp";
name[109] = "SNP";
name[110] = "Compaq-Peer";
name[111] = "IPX-in-IP";
name[112] = "VRRP";
name[113] = "PGM";
name[115] = "L2TP";
name[116] = "DDX";
name[117] = "IATP";
name[118] = "STP";
name[119] = "SRP";
name[120] = "UTI";
name[121] = "SMP";
name[122] = "SM";
name[123] = "PTP";
name[124] = "ISIS-over-IPv4";
name[125] = "FIRE";
name[126] = "CRTP";
name[127] = "CRUDP";
name[128] = "SSCOPMCE";
name[129] = "IPLT";
name[130] = "SPS";
name[131] = "PIPE";
name[132] = "SCTP";
name[133] = "FC";
name[134] = "RSVP-E2E-IGNORE";
name[135] = "Mobility Header";
name[136] = "UDPLite";
name[137] = "MPLS-in-IP";
for(i = 0;i < 256;i++){
	if(!rejected[i]){
		if( name[i] ) {
			report = strcat( report, i, "\t", name[i], "\n" );
		}
		else {
			report = strcat( report, i, "\n" );
		}
		set_kb_item( name: "IPProtocol/" + i, value: 1 );
	}
}
log_message( port: 0, data: report );
set_kb_item( name: "Host/protocol_scanned", value: 1 );
if(debug_level){
	display( "ip_protocol_scan(", d, ") ran in ", unixtime() - start_time, " s\\n" );
}

