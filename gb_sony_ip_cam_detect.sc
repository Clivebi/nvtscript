if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107105" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-09 12:56:26 +0100 (Fri, 09 Dec 2016)" );
	script_name( "Sony IPELA Engine IP Cameras Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Sony IPELA Engine IP Cameras" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
buf = http_get_cache( port: port, item: "/" );
if(!ContainsString( buf, "Sony Network Camera" ) && !ContainsString( buf, "SONY Network Camera" )){
	exit( 0 );
}
camVer = eregmatch( pattern: "[SONY|Sony] Network Camera SNC-([A-Z]+[0-9]+)", string: buf );
if( camVer[1] ){
	Ver = "SNC-" + camVer[1];
}
else {
	Ver = "Unknown";
}
set_kb_item( name: "sony/ip_camera/model", value: Ver );
cpe = "cpe:/h:sony:sony_network_camera_snc";
firmVer = eregmatch( pattern: "Server: gen[5|6]th/([0-9.]+)", string: buf );
if( firmVer[1] ){
	set_kb_item( name: "sony/ip_camera/firmware", value: firmVer[1] );
	cpe += ":" + firmVer[1];
}
else {
	set_kb_item( name: "sony/ip_camera/firmware", value: "Unknown" );
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
set_kb_item( name: "sony/ip_camera/installed", value: TRUE );
report = build_detection_report( app: "Sony IP Camera", version: firmVer[1], install: "/", cpe: cpe, extra: "Model: " + Ver );
log_message( port: port, data: report );
exit( 0 );

