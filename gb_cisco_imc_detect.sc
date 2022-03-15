if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105348" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-09-08 16:28:06 +0200 (Tue, 08 Sep 2015)" );
	script_name( "Cisco Integrated Management Controller Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(!buf = http_get_cache( port: port, item: "/" )){
	exit( 0 );
}
if(!ContainsString( buf, "<title>Cisco Integrated Management Controller Login</title>" )){
	exit( 0 );
}
vers = "unknown";
cpe = "cpe:/a:cisco:integrated_management_controller";
url = "/public/cimc.esp";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
version = eregmatch( string: buf, pattern: "var fwVersion = \"([^\"]+)\";", icase: TRUE );
if(!isnull( version[1] )){
	vers = chomp( version[1] );
	cpe += ":" + vers;
}
set_kb_item( name: "cisco_imc/installed", value: TRUE );
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Cisco Integrated Management Controller", version: vers, install: "/", cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

