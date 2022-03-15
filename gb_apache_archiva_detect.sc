if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100923" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)" );
	script_name( "Apache Archiva Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Apache Archiva.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if( !ContainsString( res, "<title>Apache Archiva" ) && !ContainsString( res, "Archiva needs Javascript" ) ){
	res = http_get_cache( port: port, item: "/archiva/index.action" );
	if( !ContainsString( res, "<title>Apache Archiva" ) || !ContainsString( res, "The Apache Software Foundation" ) || !ContainsString( res, "Artifact ID" ) ) {
		exit( 0 );
	}
	else {
		install = "/archiva";
	}
}
else {
	install = "/";
}
version = "unknown";
if( install == "/" ){
	url = "/restServices/archivaUiServices/runtimeInfoService/archivaRuntimeInfo/en";
	req = http_get_req( port: port, url: url, add_headers: make_array( "X-Requested-With", "XMLHttpRequest", "Accept", "application/json, text/javascript, */*; q=0.01" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "\"version\":\"([0-9.]+)\",", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "apache_archiva/version", value: version );
	}
}
else {
	vers = eregmatch( string: res, pattern: ">Apache Archiva( |&nbsp;-&nbsp;)([0-9.]+[^<]+)<", icase: TRUE );
	if(!isnull( vers[2] )){
		version = vers[2];
		set_kb_item( name: "apache_archiva/version", value: version );
	}
}
set_kb_item( name: "apache_archiva/installed", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.A-Z-]+)", base: "cpe:/a:apache:archiva:" );
if(!cpe){
	cpe = "cpe:/a:apache:archiva";
}
register_product( cpe: cpe, location: install, port: port, service: "www" );
log_message( data: build_detection_report( app: "Apache Archiva", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: url ), port: port );
exit( 0 );

