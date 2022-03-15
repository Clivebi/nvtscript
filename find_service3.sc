if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108198" );
	script_version( "2021-06-18T12:11:02+0000" );
	script_tag( name: "last_modification", value: "2021-06-18 12:11:02 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-07-20 14:08:04 +0200 (Thu, 20 Jul 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Service Detection with '<xml/>' Request" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service1.sc", "find_service2.sc", "find_service_3digits.sc" );
	script_require_ports( "Services/unknown" );
	script_tag( name: "summary", value: "This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a '<xml/>'
  request to the remaining unknown services and tries to identify them." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("global_settings.inc.sc");
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
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
vt_strings = get_vt_strings();
req = "<" + vt_strings["lowercase"] + "/>";
send( socket: soc, data: req + "\r\n" );
r = recv( socket: soc, length: 4096 );
close( soc );
if(!r){
	debug_print( "service on port ", port, " does not answer to \"" + req + "\\r\\n\"" );
	exit( 0 );
}
k = "FindService/tcp/" + port + "/xml";
set_kb_item( name: k, value: r );
rhexstr = hexstr( r );
if(ContainsString( r, "\0" )){
	set_kb_item( name: k + "Hex", value: rhexstr );
}
if(ContainsString( r, "oap_response" ) && ContainsString( r, "GET_VERSION" )){
	service_register( port: port, proto: "oap", message: "A OpenVAS Administrator service supporting the OAP protocol seems to be running on this port." );
	log_message( port: port, data: "A OpenVAS Administrator service supporting the OAP protocol seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "GET_VERSION" ) && ( ContainsString( r, "omp_response" ) || ContainsString( r, "gmp_response" ) )){
	service_register( port: port, proto: "omp_gmp", message: "A OpenVAS / Greenbone Vulnerability Manager supporting the OMP/GMP protocol seems to be running on this port." );
	log_message( port: port, data: "A OpenVAS / Greenbone Vulnerability Manager supporting the OMP/GMP protocol seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "<<<check_mk>>>" ) || ContainsString( r, "<<<uptime>>>" ) || ContainsString( r, "<<<services>>>" ) || ContainsString( r, "<<<mem>>>" )){
	replace_kb_item( name: "check_mk_agent/banner/" + port, value: r );
	service_register( port: port, proto: "check_mk_agent", message: "A Check_MK Agent seems to be running on this port." );
	log_message( port: port, data: "A Check_MK Agent seems to be running on this port." );
	exit( 0 );
}
if(r == "JDWP-Handshake"){
	service_register( port: port, proto: "jdwp", message: "A Java Debug Wired Protocol (JDWP) service is running at this port." );
	log_message( port: port, data: "A Java Debug Wired Protocol (JDWP) service is running at this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^5[19]000000$" )){
	service_register( port: port, proto: "fw1-topology", message: "A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
	log_message( port: port, data: "A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
	exit( 0 );
}
if(!r0){
	unknown_banner_set( port: port, banner: r );
}

