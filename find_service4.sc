if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108199" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-07-20 14:08:04 +0200 (Thu, 20 Jul 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Service Detection with 'JSON' Request" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service3.sc" );
	script_require_ports( "Services/unknown" );
	script_tag( name: "summary", value: "This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'JSON'
  request to the remaining unknown services and tries to identify them." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("global_settings.inc.sc");
require("port_service_func.inc.sc");
port = get_kb_item( "Services/unknown" );
if(!port){
	exit( 0 );
}
if(!get_port_state( port )){
	exit( 0 );
}
if(!service_is_unknown( port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "{\"request\":\"active checks\"}\n" );
r = recv( socket: soc, length: 4096 );
close( soc );
if(!r){
	debug_print( "service on port ", port, " does not answer to {\"request\":\"active checks\"}\\n", "\\n" );
	exit( 0 );
}
k = "FindService/tcp/" + port + "/json";
set_kb_item( name: k, value: r );
if(ContainsString( r, "\0" )){
	set_kb_item( name: k + "Hex", value: hexstr( r ) );
}
if(IsMatchRegexp( r, "^ZBXD" )){
	service_register( port: port, proto: "zabbix", message: "A Zabbix Server seems to be running on this port." );
	log_message( port: port, data: "A Zabbix Server seems to be running on this port." );
	exit( 0 );
}
if(r == "%7B%22request%22%3A%22active checks%22%7D\n"){
	service_register( port: port, proto: "squeezecenter_cli", message: "A Logitech SqueezeCenter/Media Server CLI service seems to be running on this port." );
	log_message( port: port, data: "A Logitech SqueezeCenter/Media Server CLI service seems to be running on this port." );
	exit( 0 );
}
if(r == "JDWP-Handshake"){
	service_register( port: port, proto: "jdwp", message: "A Java Debug Wired Protocol (JDWP) service is running at this port." );
	log_message( port: port, data: "A Java Debug Wired Protocol (JDWP) service is running at this port." );
	exit( 0 );
}
if(!r0){
	unknown_banner_set( port: port, banner: r );
}

