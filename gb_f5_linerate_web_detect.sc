if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105307" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-24 15:27:54 +0200 (Wed, 24 Jun 2015)" );
	script_name( "F5 LineRate Web Configuration Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and
 attempts to detect F5 LineRate from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8443 );
url = "/login";
;
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "<title>LineRate Login</title>" ) && ContainsString( buf, "X-Powered-By: Express" )){
	cpe = "cpe:/a:f5:linerate";
	install = "/";
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "F5 LineRate Configuration Utility", version: "unknown", install: install, cpe: cpe, concluded: "HTTP-Request" ), port: port );
}
exit( 0 );

