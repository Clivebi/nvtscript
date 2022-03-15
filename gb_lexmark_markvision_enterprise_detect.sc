if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105170" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-16 13:40:56 +0100 (Fri, 16 Jan 2015)" );
	script_name( "Lexmark MarkVision Enterprise Detection" );
	script_tag( name: "summary", value: "The script sends a connection
request to the server and attempts to extract the version number
from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9788 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9788 );
url = "/mve/help/en/inventory/am_about.html";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>About Information</title>" ) || !ContainsString( buf, "MarkVision" )){
	exit( 0 );
}
cpe = "cpe:/a:lexmark:markvision";
set_kb_item( name: "lexmark_markvision_enterprise/installed", value: TRUE );
version = "unknown";
vers = eregmatch( pattern: "<p>MarkVision[ A-Za-z]+([^<]+)</p>", string: buf );
if(!isnull( vers[1] )){
	version = vers[1];
	cpe += ":" + version;
	set_kb_item( name: "lexmark_markvision_enterprise/version", value: version );
}
b = eregmatch( pattern: "<p>Build[ ]*([^ <]+)</p>", string: buf );
if(!isnull( b[1] )){
	build = b[1];
	set_kb_item( name: "lexmark_markvision_enterprise/build", value: build );
}
register_product( cpe: cpe, location: "/mve", port: port, service: "www" );
log_message( data: build_detection_report( app: "Lexmark MarkVision Enterprise", version: version, install: "/mve", cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

