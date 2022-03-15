if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105578" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-17 17:19:28 +0100 (Thu, 17 Mar 2016)" );
	script_name( "AKIPS Network Monitor Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
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
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>AKIPS Network Monitor</title>" ) || !ContainsString( buf, "www.akips.com" )){
	exit( 0 );
}
cpe = "cpe:/a:akips:network_monitor";
set_kb_item( name: "akips_network_monitor/installed", value: TRUE );
version = eregmatch( pattern: "Version: ([0-9]+[^ ]+) ", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "akips_network_monitor/version", value: vers );
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "AKIPS Network Monitor", version: vers, install: "/", cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

