if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111019" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-04-22 08:00:00 +0200 (Wed, 22 Apr 2015)" );
	script_name( "Axway SecureTransport Detection" );
	script_tag( name: "summary", value: "Detection of the installation and version
  of a Axway SecureTransport.

  The script sends HTTP GET requests and tries to confirm the Axway SecureTransport
  installation and version from the responses." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
res = http_get_cache( item: "/", port: port );
axwayVer = "unknown";
if(concluded = eregmatch( string: banner, pattern: "Server: SecureTransport[/ ]?([0-9.]+?)", icase: TRUE )){
	if(concluded[1] && version_is_greater_equal( version: concluded[1], test_version: "5.0" )){
		installed = 1;
		axwayVer = concluded[1];
	}
}
if(res && ( ContainsString( res, "<title>Axway SecureTransport Login" ) || ContainsString( res, "<title>Axway SecureTransport | Login" ) )){
	ver = eregmatch( pattern: "\"SecureTransport\", \"([0-9.]+)\"", string: res );
	if(ver[1]){
		axwayVer = ver[1];
		concluded = ver;
	}
	installed = 1;
}
if(installed){
	set_kb_item( name: "axway_securetransport/installed", value: TRUE );
	cpe = build_cpe( value: axwayVer, exp: "([0-9a-z.]+)", base: "cpe:/a:axway:securetransport:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:axway:securetransport";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Axway SecureTransport", version: axwayVer, install: "/", cpe: cpe, concluded: concluded[0] ), port: port );
}
exit( 0 );

