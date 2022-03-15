if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11121" );
	script_version( "2021-06-11T10:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 10:04:04 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "xteld Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service2.sc", "find_service3.sc", "find_service4.sc", "find_service5.sc", "find_service6.sc", "find_service_spontaneous.sc", "find_service_3digits.sc" );
	script_require_ports( 1313 );
	script_tag( name: "summary", value: "Detection of an xteld service." );
	script_tag( name: "insight", value: "This service allows users to connect to the 'Teletel' network.
  Some of the servers are expensive. Note that by default, xteld forbids access to the most
  expensive services." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = 1313;
if(!get_port_state( port )){
	exit( 0 );
}
if(service_is_known( port: port )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
req = raw_string( 6 ) + vt_strings["default"] + raw_string( 0x82 );
m = "";
send( socket: soc, data: req );
for(;TRUE;){
	r = recv( socket: soc, length: 1 );
	if(strlen( r ) == 0){
		break;
	}
	len = ord( r );
	if(len == 130){
		break;
	}
	r1 = recv( socket: soc, length: len );
	send( socket: soc, data: raw_string( 0x83 ) );
	r = recv( socket: soc, length: 1 );
	if(strlen( r ) == 0){
		break;
	}
	len = ord( r );
	if(len == 130){
		break;
	}
	r2 = recv( socket: soc, length: len );
	send( socket: soc, data: raw_string( 0x82 ) );
	m = NASLString( m, r1, " - ", r2, "\\n" );
}
close( soc );
if(strlen( m ) > 0){
	service_register( port: port, proto: "xtel" );
	log_message( port: port, data: "Authorized services:\n" + m );
}
exit( 0 );

