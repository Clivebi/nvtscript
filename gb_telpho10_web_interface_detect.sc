if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140075" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-11-21 13:13:46 +0100 (Mon, 21 Nov 2016)" );
	script_name( "telpho10 Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of telpho10 telephone system." );
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
url = "/telpho/login.php";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>telpho10" ) || !ContainsString( buf, "telpho GmbH" )){
	exit( 0 );
}
cpe = "cpe:/a:telpho:telpho10";
set_kb_item( name: "telpho10/webinterface/detected", value: TRUE );
vers = "unknown";
version = eregmatch( pattern: "telpho10 Version ([0-9.]+[^ \r\n]+)", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "telpho10/version", value: vers );
}
register_product( cpe: cpe, location: "/telpho", port: port, service: "www" );
report = build_detection_report( app: "telpho10", version: vers, install: "/telpho", cpe: cpe, concluded: version[0] );
log_message( port: port, data: report );
exit( 0 );

