if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100867" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-10-22 14:10:21 +0200 (Fri, 22 Oct 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Sawmill Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8988 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running Sawmill, a hierarchical log analysis tool." );
	script_xref( name: "URL", value: "http://www.sawmill.net" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8988 );
banner = http_get_remote_headers( port: port );
buf = http_get_cache( item: "/", port: port );
if(( !banner || !ContainsString( banner, "erver: Sawmill" ) ) && !ContainsString( buf, "<title>Sawmill" ) && !ContainsString( buf, "/picts/sawmill_logo.png" )){
	exit( 0 );
}
vers = "unknown";
version = eregmatch( string: banner, pattern: "Server: Sawmill/([0-9.]+)", icase: TRUE );
if(!isnull( version[1] )){
	vers = chomp( version[1] );
}
set_kb_item( name: "www/" + port + "/sawmill", value: vers );
set_kb_item( name: "sawmill/installed", value: TRUE );
cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:sawmill:sawmill:" );
if(isnull( cpe )){
	cpe = "cpe:/a:sawmill:sawmill";
}
register_product( cpe: cpe, location: port + "/tcp", port: port, service: "www" );
log_message( data: build_detection_report( app: "Sawmill", version: vers, install: port + "/tcp", cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

