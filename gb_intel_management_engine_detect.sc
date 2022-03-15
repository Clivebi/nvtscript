if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812220" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-11-22 12:31:00 +0530 (Wed, 22 Nov 2017)" );
	script_name( "Intel Management Engine (ME) Firmware Version Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the
 server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 16992 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
imeport = http_get_port( default: 16992 );
banner = http_get_remote_headers( port: imeport );
if(!ContainsString( banner, "Server: Intel(R) Con. Management Engine" )){
	exit( 0 );
}
set_kb_item( name: "intel_me/installed", value: TRUE );
vers = "unknown";
cpe = "cpe:/h:intel:management_engine";
version = eregmatch( pattern: "Server: Intel\\(R\\) Con. Management Engine ([0-9.]+)", string: banner );
if(version[1]){
	vers = version[1];
	cpe += ":" + vers;
}
register_product( cpe: cpe, location: "/", port: imeport, service: "www" );
log_message( data: build_detection_report( app: "Intel Management Engine", version: vers, install: "/", cpe: cpe, concluded: version[0] ), port: imeport );
exit( 0 );

