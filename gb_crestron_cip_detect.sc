if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141365" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-08-14 13:10:06 +0700 (Tue, 14 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Crestron Device Detection (CIP)" );
	script_tag( name: "summary", value: "Detection of Crestron devices.

The script sends a Crestron Internet Protocol (CIP) connection request to the server and attempts to detect
Crestron devices and to extract its firmware version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_require_udp_ports( 41794 );
	script_xref( name: "URL", value: "https://www.crestron.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
port = 41794;
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_priv_sock_udp( dport: port, sport: port );
if(!soc){
	exit( 0 );
}
host = get_host_name();
len = 256 - strlen( host );
query = raw_string( 0x14, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x03, 0x00, 0x00, host, crap( data: raw_string( 0x00 ), length: len ) );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 4096 );
close( soc );
if(!recv || hexstr( recv[0] ) != "15" || strlen( recv ) < 266){
	exit( 0 );
}
model = "unknown";
version = "unknown";
hostname = bin2string( ddata: substr( recv, 10, 40 ), noprint_replacement: "" );
extra = "Hostname:    " + hostname + "\n";
data = bin2string( ddata: substr( recv, 266 ), noprint_replacement: "" );
mod = eregmatch( pattern: "(.*) \\[", string: data );
if( !isnull( mod[1] ) ){
	model = mod[1];
	os_name = "Crestron " + model + " Firmware";
	cpe_model = split( buffer: model, sep: " ", keep: FALSE );
	cpe_model = tolower( cpe_model[0] );
}
else {
	os_name = "Crestron Unknown Model Firmware";
	cpe_model = "unknown_model";
}
vers = eregmatch( pattern: "\\[v([0-9.]+)", string: data );
if(!isnull( vers[1] )){
	version = vers[1];
}
build = eregmatch( pattern: " \\(([^)]+)", string: data );
if(!isnull( build[1] )){
	extra += "Build Date:  " + build[1];
}
set_kb_item( name: "crestron_device/detected", value: TRUE );
service_register( port: port, proto: "crestron-cip", ipproto: "udp" );
if( IsMatchRegexp( model, "^AM-" ) ){
	set_kb_item( name: "crestron_airmedia/detected", value: TRUE );
	set_kb_item( name: "crestron_airmedia/cip/detected", value: TRUE );
	set_kb_item( name: "crestron_airmedia/cip/port", value: port );
	set_kb_item( name: "crestron_airmedia/cip/" + port + "/model", value: model );
	set_kb_item( name: "crestron_airmedia/cip/" + port + "/fw_version", value: version );
}
else {
	os_cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/o:crestron:" + cpe_model + "_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:crestron:" + cpe_model + "_firmware";
	}
	hw_cpe = "cpe:/h:crestron:" + cpe_model;
	os_register_and_report( os: os_name, cpe: os_cpe, desc: "Crestron Device Detection (CIP)", runs_key: "unixoide" );
	register_product( cpe: os_cpe, location: port + "/udp", port: port, proto: "udp", service: "crestron-cip" );
	register_product( cpe: hw_cpe, location: port + "/udp", port: port, proto: "udp", service: "crestron-cip" );
	log_message( data: build_detection_report( app: os_name, version: version, install: port + "/udp", cpe: os_cpe, extra: extra ), port: port, proto: "udp" );
}
exit( 0 );

