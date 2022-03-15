if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113757" );
	script_version( "2021-05-14T13:11:51+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "discard Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 StrongHoldNet" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 9 );
	script_tag( name: "summary", value: "Checks whether the discard service is running
  on the target host." );
	script_tag( name: "insight", value: "The discard service sets up a listening socket
  and then ignores all data it receives." );
	exit( 0 );
}
CPE = "cpe:/a:postel:discard";
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = 9;
if(!service_is_unknown( port: port )){
	exit( 0 );
}
func check_discard( soc ){
	var n, res;
	if(!soc){
		return ( 0 );
	}
	n = send( socket: soc, data: NASLString( crap( length: ( rand() % 193 + 17 ), data: NASLString( rand() ) ), "\\r\\n\\r\\n" ) );
	if(n < 0){
		return ( 0 );
	}
	res = recv( socket: soc, length: 1024, timeout: 5 );
	if(strlen( res ) > 0){
		return ( 0 );
	}
	return ( 1 );
}
if(get_port_state( port )){
	soc = open_sock_tcp( port );
	if(check_discard( soc )){
		set_kb_item( name: "discard/port", value: port );
		set_kb_item( name: "discard/detected", value: TRUE );
		service_register( port: port, proto: "discard" );
		register_product( cpe: CPE, location: port + "/tcp", port: port, service: "discard" );
		report = build_detection_report( app: "discard", cpe: CPE, skip_version: TRUE );
		log_message( data: report, port: port );
	}
}
exit( 0 );

