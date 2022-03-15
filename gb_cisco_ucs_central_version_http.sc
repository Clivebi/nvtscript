if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105572" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-17 13:41:17 +0100 (Thu, 17 Mar 2016)" );
	script_name( "Cisco UCS Central Detectioni (HTTP)" );
	script_tag( name: "summary", value: "This Script performs HTTP based detection of Cisco UCS Central" );
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
source = "http";
port = http_get_port( default: 443 );
url = "/ui/faces/Login.xhtml";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>UCS Central</title>" ) || !ContainsString( buf, "/cisco/" ) || !ContainsString( buf, "Cisco UCS Central" )){
	exit( 0 );
}
cpe = "cpe:/a:cisco:ucs_central_software";
set_kb_item( name: "cisco_ucs_central/installed", value: TRUE );
set_kb_item( name: "cisco_ucs_central/" + source + "/port", value: port );
vers = "unknown";
version = eregmatch( pattern: "/ui/resources/static/([0-9.]+[^/]+)/cisco/", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	vers = str_replace( string: vers, find: "_", replace: "(" );
	vers += ")";
	cpe += ":" + vers;
	set_kb_item( name: "cisco_ucs_central/" + source + "/version", value: vers );
}
report = build_detection_report( app: "Cisco UCS Central", version: vers, install: "HTTP(s)", cpe: cpe, concluded: version[0] );
log_message( port: port, data: report );
exit( 0 );

