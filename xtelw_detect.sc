if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11120" );
	script_version( "2021-06-11T10:16:40+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 10:16:40 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "xtelw Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service2.sc", "find_service3.sc", "find_service4.sc", "find_service5.sc", "find_service6.sc", "find_service_spontaneous.sc", "find_service_3digits.sc" );
	script_require_ports( 1314 );
	script_tag( name: "summary", value: "Detection of an xteld service running in HyperTerminal mode." );
	script_tag( name: "insight", value: "This service allows users to connect to the 'Teletel' network.
  Some of the servers are expensive. Note that by default, xteld forbids access to the most
  expensive services." );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("string_hex_func.inc.sc");
port = 1314;
if(!get_port_state( port )){
	exit( 0 );
}
if(service_is_known( port: port )){
	exit( 0 );
}
banner = unknown_banner_get( port: port, dontfetch: FALSE );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "Service Minitel" ) && ContainsString( banner, "Xteld" )){
	service_register( port: port, proto: "xtelw" );
	log_message( port: port );
}
exit( 0 );

