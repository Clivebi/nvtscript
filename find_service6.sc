if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108204" );
	script_version( "2021-07-12T08:59:04+0000" );
	script_tag( name: "last_modification", value: "2021-07-12 08:59:04 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2017-08-04 09:08:04 +0200 (Fri, 04 Aug 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Service Detection with 'BINARY' Request" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service5.sc" );
	script_require_ports( "Services/unknown" );
	script_tag( name: "summary", value: "This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'BINARY'
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
req = raw_string( 0x00, 0x01, 0x02, 0x03, 0x04 );
send( socket: soc, data: req );
r = recv( socket: soc, length: 4096 );
close( soc );
if(!r){
	debug_print( "service on port ", port, " does not answer to a \"0x00, 0x01, 0x02, 0x03, 0x04\" raw string request", "\\n" );
	exit( 0 );
}
rhexstr = hexstr( r );
k = "FindService/tcp/" + port + "/bin";
set_kb_item( name: k, value: r );
if(ContainsString( r, "\0" )){
	set_kb_item( name: k + "Hex", value: rhexstr );
}
if(ContainsString( r, "rlogind: Permission denied." )){
	service_register( port: port, proto: "rlogin", message: "A rlogin service seems to be running on this port." );
	log_message( port: port, data: "A rlogin service seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "Where are you?" )){
	service_register( port: port, proto: "rexec", message: "A rexec service seems to be running on this port." );
	log_message( port: port, data: "A rexec service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^SSH-2.0-libssh[_-][0-9.]+[^\\r\\n]+$" ) || r == "SSH-2.0-libssh\n"){
	service_register( port: port, proto: "ssh", message: "A SSH service seems to be running on this port." );
	log_message( port: port, data: "A SSH service seems to be running on this port." );
	replace_kb_item( name: "SSH/server_banner/" + port, value: chomp( r ) );
	exit( 0 );
}
if(rhexstr == "0011496e76616c696420636f6d6d616e640a000000"){
	service_register( port: port, proto: "apcupsd", message: "A apcupsd service seems to be running on this port." );
	log_message( port: port, data: "A apcupsd service seems to be running on this port." );
	exit( 0 );
}
if(r == "JDWP-Handshake"){
	service_register( port: port, proto: "jdwp", message: "A Java Debug Wired Protocol (JDWP) service is running at this port." );
	log_message( port: port, data: "A Java Debug Wired Protocol (JDWP) service is running at this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "013939393946463142.." )){
	service_register( port: port, proto: "automated-tank-gauge", message: "A Automated Tank Ggauge (ATG) service seems to be running on this port." );
	log_message( port: port, data: "A Automated Tank Gauge (ATG) service seems to be running on this port." );
	exit( 0 );
}
if(port == 13724 && rhexstr == "3100"){
	service_register( port: port, proto: "vnetd", message: "A Veritas Network Utility service seems to be running on this port." );
	log_message( port: port, data: "A Veritas Network Utility service seems to be running on this port." );
	exit( 0 );
}
if(!r0){
	unknown_banner_set( port: port, banner: r );
}

