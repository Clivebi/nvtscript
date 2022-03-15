if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108892" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-27 11:22:12 +0000 (Thu, 27 Aug 2020)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Visionsoft Audit Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "find_service1.sc" );
	script_require_ports( "Services/visionsoft-audit", 5957 );
	script_tag( name: "summary", value: "Detection of Visionsoft Audit based on the
  Visionsoft Audit on Demand Service." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = service_get_port( default: 5957, proto: "visionsoft-audit" );
sock = open_sock_tcp( port );
if(!sock){
	exit( 0 );
}
banner = recv_line( socket: sock, length: 1024 );
if(!banner || !ContainsString( banner, "Visionsoft Audit on Demand Service" )){
	close( sock );
	exit( 0 );
}
set_kb_item( name: "visionsoft/audit/detected", value: TRUE );
install = port + "/tcp";
version = "unknown";
concl = chomp( banner );
vers_banner = recv_line( socket: sock, length: 1024 );
close( sock );
vers = eregmatch( string: vers_banner, pattern: "Version: ([0-9.]+)", icase: FALSE );
if(vers[1]){
	version = vers[1];
	concl += "\n" + vers[0];
}
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:visionsoft:audit:" );
if(!cpe){
	cpe = "cpe:/a:visionsoft:audit";
}
service_register( port: port, proto: "visionsoft-audit" );
register_product( cpe: cpe, location: install, port: port, service: "visionsoft-audit" );
log_message( data: build_detection_report( app: "Visionsoft Audit", version: version, install: install, cpe: cpe, concluded: concl ), port: port );
exit( 0 );

