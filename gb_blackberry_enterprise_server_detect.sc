if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106518" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-01-16 10:12:31 +0700 (Mon, 16 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "BlackBerry Enterprise Server Detection" );
	script_tag( name: "summary", value: "Detection of BlackBerry Enterprise Server

The script sends a HTTP connection request to the server and attempts to detect the presence of BlackBerry
Enterprise Server and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( res, "<title>BES[0-9]+ Self-Service</title>" ) && ContainsString( res, "window.BESC_HELP" )){
	version = "unknown";
	vers = eregmatch( pattern: "window.UOS_MARKETING_VERSION = \"([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "blackberry_bes/version", value: version );
	}
	set_kb_item( name: "blackberry_bes/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:blackberry:enterprise_server:" );
	if(!cpe){
		cpe = "cpe:/a:blackberry:enterprise_server";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "BlackBerry Enterprise Server", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

