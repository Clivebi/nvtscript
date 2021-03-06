if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146546" );
	script_version( "2021-08-24T11:36:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 11:36:18 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-23 14:16:29 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2003-0001", "CVE-2017-2304", "CVE-2021-3031" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ICMP 'EtherLeak' Information Disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "host_alive_detection.sc", "os_fingerprint.sc", "global_settings.sc" );
	script_exclude_keys( "keys/islocalhost", "keys/TARGET_IS_IPV6", "ICMPv4/EchoRequest/failed" );
	script_tag( name: "summary", value: "The remote host is prone to an information disclosure
  vulnerability over ICMP (EtherLeak)." );
	script_tag( name: "vuldetect", value: "Sends multiple crafted ICMP packets and checks the responses." );
	script_tag( name: "insight", value: "Multiple ethernet Network Interface Card (NIC) device drivers
  do not pad frames with null bytes, which allows remote attackers to obtain information from
  previous packets or kernel memory by using malformed packets, as demonstrated by EtherLeak." );
	script_tag( name: "impact", value: "An unauthenticated attacker might gather sensitive information." );
	script_tag( name: "solution", value: "Contact the vendor of the network device driver for a solution." );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/412115" );
	script_xref( name: "URL", value: "https://dl.packetstormsecurity.net/advisories/atstake/atstake_etherleak_report.pdf" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/3555" );
	exit( 0 );
}
require("dump.inc.sc");
if(TARGET_IS_IPV6()){
	exit( 0 );
}
if(islocalhost()){
	exit( 0 );
}
if(get_kb_item( "ICMPv4/EchoRequest/failed" )){
	exit( 0 );
}
own_ip = this_host();
target_ip = get_host_ip();
icmp_ping_request = 8;
icmp_ping_reply = 0;
icmp_id = rand() % 65536;
ip = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_off: 0, ip_id: 9, ip_tos: 0, ip_p: IPPROTO_ICMP, ip_len: 46, ip_src: own_ip, ip_ttl: 255 );
icmp = forge_icmp_packet( ip: ip, icmp_type: icmp_ping_request, icmp_code: 0, icmp_seq: 1, icmp_id: icmp_id, data: "X" );
filter = NASLString( "icmp and src host ", target_ip, " and dst host ", own_ip, " and icmp[0:1] = ", icmp_ping_reply );
for(i = 0;i < 5;i++){
	recv = send_packet( packet: icmp, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: 3 );
	if(!recv){
		continue;
	}
	data = get_icmp_element( icmp: recv, element: "data" );
	if(data && data[0] == "X"){
		padding = substr( data, 1, strlen( data ) - 4 );
		nonnull_padding = str_replace( string: padding, find: raw_string( 0x00 ), replace: "" );
		if(strlen( nonnull_padding ) != 0){
			report = "Non-null padding observed in the following data frame:\n\n" + hexdump( ddata: data );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

