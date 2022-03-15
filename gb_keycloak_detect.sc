if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140066" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-11-17 10:30:27 +0100 (Thu, 17 Nov 2016)" );
	script_name( "Keycloak Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to detect Keycloak and also to extract its version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/auth/";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>Welcome to Keycloak</title>" ) || !ContainsString( buf, ">Administration Console<" )){
	exit( 0 );
}
set_kb_item( name: "keycloak/detected", value: TRUE );
cpe = "cpe:/a:redhat:keycloak";
url = "/auth/admin/master/console/";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
v = eregmatch( pattern: "/auth/resources/([0-9.]+)\\.([a-z]+[^/]+)/admin/", string: buf );
if(!isnull( v[1] )){
	version = v[1];
	cpe += ":" + version;
	rep_version = version;
}
if(!isnull( v[2] )){
	set_kb_item( name: "keycloak/release_type", value: v[2] );
	rep_version += " (" + v[2] + ")";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
report = build_detection_report( app: "Keycloak", version: rep_version, install: "/", cpe: cpe, concluded: v[0] );
log_message( port: port, data: report );
exit( 0 );

