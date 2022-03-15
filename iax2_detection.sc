if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20834" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Inter-Asterisk eXchange Protocol Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2006 Ferdy Riphagen" );
	script_require_udp_ports( 4569 );
	script_tag( name: "solution", value: "If possible, filter incoming connections to the port so that it is used by
trusted sources only." );
	script_tag( name: "summary", value: "The remote system is running a server that speaks the Inter-Asterisk eXchange
Protocol.

Description :

The Inter-Asterisk eXchange protocol (IAX2) is used by the Asterisk PBX Server and other IP Telephony
clients/servers to enable voice communication between them." );
	script_xref( name: "URL", value: "http://en.wikipedia.org/wiki/IAX" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = 4569;
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_sock_udp( port );
poke_msg = raw_string( 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x1E );
send( socket: soc, data: poke_msg );
recv = recv( socket: soc, length: 128 );
if(recv == NULL){
	exit( 0 );
}
if(strlen( recv ) != 12){
	exit( 0 );
}
if(ord( recv[10] ) == 6 && ( ord( recv[11] ) == 3 || ord( recv[11] ) == 4 )){
	log_message( port );
	service_register( ipproto: "udp", proto: "iax2", port: port );
	exit( 0 );
}
exit( 0 );

