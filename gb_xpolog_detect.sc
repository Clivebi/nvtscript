if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105807" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-12 14:42:48 +0200 (Tue, 12 Jul 2016)" );
	script_name( "XpoLog Center Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = "/logeye/security/auth/login.jsp";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>XpoLog Center Login</title>" ) || !ContainsString( buf, "Contact XpoLog's support" )){
	exit( 0 );
}
set_kb_item( name: "xpolog_center/installed", value: TRUE );
cpe = "cpe:/a:xpolog:xpolog_center";
vers = "unknown";
v_b = eregmatch( pattern: "XpoLog Center ([0-9]+)\\s*build ([0-9]+)", string: buf );
if(!isnull( v_b[1] )){
	vers = v_b[1];
	cpe += ":" + vers;
}
if(!isnull( v_b[2] )){
	vers += "." + v_b[2];
	cpe += "." + v_b[2];
}
register_product( cpe: cpe, location: "/logeye/security/auth/", port: port, service: "www" );
report = build_detection_report( app: "XpoLog Center", version: vers, install: "/logeye/security/auth/", cpe: cpe, concluded: v_b[0], concludedUrl: url );
log_message( port: port, data: report );
exit( 0 );

