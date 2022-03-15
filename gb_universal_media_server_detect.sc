if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141351" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-07 08:19:49 +0700 (Tue, 07 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Universal Media Server Detection" );
	script_tag( name: "summary", value: "Detection of Universal Media Server.

The script sends a connection request to the server and attempts to detect Universal Media Server and to extract
its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.universalmediaserver.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>Universal Media Server" ) && ContainsString( res, "<a href=\"/browse/0\"" )){
	version = "unknown";
	req = http_get( port: port, item: "/doc" );
	res = http_keepalive_send_recv( port: port, data: req );
	url = eregmatch( pattern: "href=\"(/files/log/-[0-9]+)\">debug.log", string: res );
	if(!isnull( url[1] )){
		req = http_get( port: port, item: url[1] );
		res = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "Starting Universal Media Server ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url[1], url_only: TRUE );
		}
	}
	set_kb_item( name: "universal_media_server/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:universal_media_server:universal_media_server:" );
	if(!cpe){
		cpe = "cpe:/a:universal_media_server:universal_media_server";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Universal Media Server", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

