if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105387" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-09-25 13:13:41 +0200 (Fri, 25 Sep 2015)" );
	script_name( "Open-Xchange App Suite Detection" );
	script_tag( name: "summary", value: "Detection of Open-Xchange App Suite.

The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.open-xchange.com/portfolio/ox-app-suite/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/appsuite/apps/io.ox/help/style.less";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( buf, "(Open-Xchange Inc.,)|(OX Software GmbH)" )){
	exit( 0 );
}
url = "/appsuite/signin";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "window.ox" ) || !ContainsString( buf, "io-ox-copyright" )){
	exit( 0 );
}
cpe = "cpe:/a:open-xchange:open-xchange_appsuite";
vers = "unknown";
set_kb_item( name: "open_xchange_appsuite/installed", value: TRUE );
version = eregmatch( pattern: "script src=\"v=([^-]+)-([0-9]+)", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
}
if(!isnull( version[2] )){
	set_kb_item( name: "open_xchange_appsuite/" + port + "/revision", value: version[2] );
}
register_product( cpe: cpe, location: "/appsuite", port: port, service: "www" );
log_message( data: build_detection_report( app: "Open-Xchange App Suite", version: vers, install: "/appsuite", cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

