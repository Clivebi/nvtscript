if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140436" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-18 13:56:42 +0700 (Wed, 18 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "3CX Phone System Detection" );
	script_tag( name: "summary", value: "Detection of 3CX Phone System.

The script sends a connection request to the server and attempts to detect 3CX Phone System and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 5000, 5001 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.3cx.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 5001 );
res = http_get_cache( port: port, item: "/#/login" );
if(ContainsString( res, "<title>3CX Phone System Management Console</title>" ) && ContainsString( res, "public/app.js" )){
	version = "unknown";
	url = "/public/app.js";
	req = http_get( port: port, item: url );
	res = http_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "\"version\",\"([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "3cx_phone_system/version", value: version );
		concUrl = url;
	}
	set_kb_item( name: "3cx_phone_system/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:3cx:phone_system:" );
	if(!cpe){
		cpe = "cpe:/a:3cx:phone_system";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "3CX Phone System", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

