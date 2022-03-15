if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10742" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Amanda Index Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Service detection" );
	script_require_ports( 10082 );
	script_dependencies( "find_service.sc" );
	script_tag( name: "summary", value: "This test detects the Amanda Index Server's
  version by connecting to the server and processing the buffer received." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Amanda Index Server version";
port = 10082;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
res = recv_line( socket: soc, length: 1000 );
close( soc );
if(!ContainsString( res, "AMANDA index server" )){
	exit( 0 );
}
version = "unknown";
install = port + "/tcp";
service_register( port: port, proto: "amandaidx" );
set_kb_item( name: "amanda/index_server/detected", value: TRUE );
if(concl = ereg( pattern: "^220 .* AMANDA index server \\(.*\\).*", string: res )){
	version = ereg_replace( pattern: "^220 .* AMANDA index server \\((.*)\\).*", string: res, replace: "\\1" );
	set_kb_item( name: "amanda/index_server/version", value: version );
}
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:amanda:amanda:" );
if(isnull( cpe )){
	cpe = "cpe:/a:amanda:amanda:";
}
register_product( cpe: cpe, location: install, port: port );
log_message( data: build_detection_report( app: "Amanda Index Server", version: version, install: port, cpe: cpe, concluded: concl ), port: port );
exit( 0 );

