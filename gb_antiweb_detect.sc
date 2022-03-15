if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106885" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-06-20 12:31:58 +0700 (Tue, 20 Jun 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Anti-Web Server Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Anti-Web web server.

  The script sends a connection request to the server and attempts to detect Anti-Web web server and to extract
  its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Anti-Web/banner" );
	script_xref( name: "URL", value: "https://github.com/hoytech/antiweb" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Anti-Web" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "Anti-Web V([0-9a-z.-]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "antiweb/version", value: version );
}
set_kb_item( name: "antiweb/installed", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9a-z.-]+)", base: "cpe:/a:anti-web:anti-web:" );
if(!cpe){
	cpe = "cpe:/a:anti-web:anti-web";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Anti-Web", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );
