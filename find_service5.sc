if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108203" );
	script_version( "2021-06-18T05:13:17+0000" );
	script_tag( name: "last_modification", value: "2021-06-18 05:13:17 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-08-04 09:08:04 +0200 (Fri, 04 Aug 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Service Detection with 'SIP' Request" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service4.sc" );
	script_require_ports( "Services/unknown" );
	script_tag( name: "summary", value: "This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'SIP' OPTIONS
  request to the remaining unknown services and tries to identify them." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("global_settings.inc.sc");
require("sip.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
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
proto = "tcp";
soc = sip_open_socket( port: port, proto: proto );
if(!soc){
	exit( 0 );
}
req = sip_construct_options_req( port: port, proto: proto );
send( socket: soc, data: req );
r = recv( socket: soc, length: 4096 );
close( soc );
if(!r){
	debug_print( "service on port ", port, " does not answer to a \"SIP OPTIONS\" request", "\\n" );
	exit( 0 );
}
k = "FindService/tcp/" + port + "/sip";
set_kb_item( name: k, value: r );
if(ContainsString( r, "\0" )){
	set_kb_item( name: k + "Hex", value: hexstr( r ) );
}
rhexstr = hexstr( r );
if(sip_verify_banner( data: r )){
	service_register( port: port, proto: "sip", message: "A service supporting the SIP protocol was idendified." );
	log_message( port: port, data: "A service supporting the SIP protocol was idendified." );
	exit( 0 );
}
if(ContainsString( r, "<<<check_mk>>>" ) || ContainsString( r, "<<<uptime>>>" ) || ContainsString( r, "<<<services>>>" ) || ContainsString( r, "<<<mem>>>" )){
	replace_kb_item( name: "check_mk_agent/banner/" + port, value: r );
	service_register( port: port, proto: "check_mk_agent", message: "A Check_MK Agent seems to be running on this port." );
	log_message( port: port, data: "A Check_MK Agent seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^61637070000[0-9]000[0-9]" )){
	service_register( port: port, proto: "airport-admin", message: "A Apple AirPort Admin service seems to be running on this port." );
	log_message( port: port, data: "A Apple AirPort Admin service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^70027761$" )){
	service_register( port: port, proto: "activemq_mqtt", message: "A ActiveMQ MQTT service seems to be running on this port." );
	log_message( port: port, data: "A ActiveMQ MQTT service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^RTSP/1\\.[0-9]+" ) && ( ContainsString( r, "CSeq: " ) || ContainsString( r, "Public: " ) || ContainsString( r, "Server: " ) )){
	service_register( port: port, proto: "rtsp", message: "A streaming server seems to be running on this port." );
	log_message( port: port, data: "A streaming server seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^This is not a HTTP port$" )){
	service_register( port: port, proto: "elasticsearch", message: "An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
	log_message( port: port, data: "An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
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

