if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10006" );
	script_version( "2019-04-11T14:06:24+0000" );
	script_tag( name: "last_modification", value: "2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "pcAnywhere" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 1999 Mathieu Perrin" );
	script_family( "Service detection" );
	script_require_udp_ports( 5632 );
	script_tag( name: "solution", value: "Disable this service if you do not use it." );
	script_tag( name: "summary", value: "pcAnywhere is running on this port." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
port = 5632;
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "ST" );
buf = recv( socket: soc, length: 2 );
close( soc );
if(ContainsString( buf, "ST" )){
	log_message( port: port, protocol: "udp" );
}

