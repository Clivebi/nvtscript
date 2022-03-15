if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140694" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-01-19 15:48:31 +0700 (Fri, 19 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "AB Ethernet Protocol (CSP) Detection" );
	script_tag( name: "summary", value: "An AB Ethernet (CSP) Service is running at this host.

AB Ethernet or CSP is used by Allen Bradley inside of its software products such as RSLinx to  communicate to the
PLCs." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 2222 );
	script_xref( name: "URL", value: "http://ab.rockwellautomation.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("byte_func.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 2222 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
query = raw_string( 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 512 );
close( soc );
if(!recv || hexstr( substr( recv, 0, 1 ) ) != "0201"){
	exit( 0 );
}
set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
session_id = getdword( blob: recv, pos: 4 );
service_register( port: port, ipproto: "tcp", proto: "csp" );
report = "An A/B Ethernet (CSP) service is running at this port.\n\nThe following session ID has been given:\n\n" + "Session ID:      " + session_id + "\n";
log_message( port: port, data: report );
exit( 0 );

