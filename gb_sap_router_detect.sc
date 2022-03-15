if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105034" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-05-27 14:06:45 +0200 (Tue, 27 May 2014)" );
	script_name( "SAProuter Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/unknown", 3299 );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
require("cpe.inc.sc");
require("byte_func.inc.sc");
require("host_details.inc.sc");
port = unknownservice_get_port( default: 3299 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x00, 0x00, 0x27, 0x29 );
send( socket: soc, data: req );
buf = recv( socket: soc, min: 4, length: 4 );
if(!buf || strlen( buf ) < 3){
	close( soc );
	exit( 0 );
}
len = getdword( blob: buf );
if(!len || int( len ) <= 0){
	close( soc );
	exit( 0 );
}
buf = recv( socket: soc, length: len );
close( soc );
if(!buf || !ContainsString( buf, "SAProuter" )){
	exit( 0 );
}
set_kb_item( name: "SAProuter/installed", value: TRUE );
service_register( port: port, proto: "SAProuter" );
buf = bin2string( ddata: buf, noprint_replacement: " " );
vers = "unknown";
version = eregmatch( pattern: "SAProuter ([0-9.]+( \\((SP[0-9]+)\\))?) on '", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
}
if(!isnull( version[3] )){
	SP = version[3];
}
cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:sap:network_interface_router:" );
if( !cpe ) {
	cpe = "cpe:/a:sap:network_interface_router";
}
else {
	if(SP){
		cpe += ":" + tolower( SP );
	}
}
register_product( cpe: cpe, location: port + "/tcp", port: port );
log_message( data: build_detection_report( app: "SAProuter", version: vers, install: port + "/tcp", cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

