if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108894" );
	script_version( "2021-04-14T12:07:16+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 12:07:16 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-08-27 13:32:10 +0000 (Thu, 27 Aug 2020)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Chargen Service Detection (UDP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gb_open_udp_ports.sc" );
	script_require_udp_ports( "Services/udp/unknown", 19 );
	script_tag( name: "summary", value: "UDP based detection of a 'chargen' service." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 19, ipproto: "udp" );
if(!soc = open_sock_udp( port )){
	exit( 0 );
}
send( socket: soc, data: "\r\n" );
banner = recv( socket: soc, length: 1024 );
close( soc );
if(!banner){
	exit( 0 );
}
chargen_found = 0;
for chargen_pattern in make_list( "!\"#$%&\'()*+,-./",
	 "ABCDEFGHIJ",
	 "abcdefg",
	 "0123456789" ) {
	if(ContainsString( banner, chargen_pattern )){
		chargen_found++;
	}
}
if(chargen_found > 2){
	set_kb_item( name: "chargen/udp/detected", value: TRUE );
	set_kb_item( name: "chargen/udp/" + port + "/detected", value: TRUE );
	service_register( port: port, proto: "chargen", message: "A chargen service seems to be running on this port.", ipproto: "udp" );
	log_message( port: port, data: "A chargen service seems to be running on this port.", proto: "udp" );
}
exit( 0 );

