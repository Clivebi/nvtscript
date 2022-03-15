if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141174" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-06-13 08:39:58 +0700 (Wed, 13 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Crestron Device Detection (CTP)" );
	script_tag( name: "summary", value: "Detection of Crestron devices.

  The script sends a Crestron Terminal Protocol (CTP) connection request to the server and attempts to detect
  Crestron devices and to extract its firmware version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 41795 );
	script_xref( name: "URL", value: "https://www.crestron.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("telnet_func.inc.sc");
require("port_service_func.inc.sc");
port = telnet_get_port( default: 41795 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: raw_string( 0x0d ) );
recv = recv( socket: soc, length: 100 );
if(!IsMatchRegexp( recv, "(Control|MC3|CP3) Console" )){
	close( soc );
	exit( 0 );
}
version = "unknown";
model = "unknown";
install = port + "/tcp";
set_kb_item( name: "crestron_device/detected", value: TRUE );
send( socket: soc, data: raw_string( 0x0d, "showhw", 0x0d ) );
recv = recv( socket: soc, length: 512 );
if(recv){
	concl = recv;
}
mod = eregmatch( pattern: "Processor Type:([^\r]+)", string: recv );
if( !isnull( mod[1] ) ){
	model = ereg_replace( pattern: "(\t| )", string: mod[1], replace: "" );
	os_name = "Crestron " + model + " Firmware";
	cpe_model = tolower( model );
}
else {
	os_name = "Crestron Unknown Model Firmware";
	cpe_model = "unknown_model";
}
send( socket: soc, data: raw_string( 0x0d, "ver", 0x0d ) );
recv = recv( socket: soc, length: 512 );
if(recv){
	concl += "\n" + recv;
}
close( soc );
vers = eregmatch( pattern: "\\[v([0-9.]+)", string: recv );
if(!isnull( vers[1] )){
	version = vers[1];
}
service_register( port: port, proto: "crestron-ctp" );
os_cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/o:crestron:" + cpe_model + "_firmware:" );
if(!os_cpe){
	os_cpe = "cpe:/o:crestron:" + cpe_model + "_firmware";
}
hw_cpe = "cpe:/h:crestron:" + cpe_model;
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Crestron Device Detection (CTP)", runs_key: "unixoide" );
register_product( cpe: os_cpe, location: install, port: port, service: "crestron-ctp" );
register_product( cpe: hw_cpe, location: install, port: port, service: "crestron-ctp" );
log_message( data: build_detection_report( app: os_name, version: version, install: install, cpe: os_cpe, concluded: concl ), port: port );
exit( 0 );

