if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811770" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-09-18 16:20:30 +0530 (Mon, 18 Sep 2017)" );
	script_name( "Mako Web Server Detection (HTTP)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Mako Web Server.

  This script sends an HTTP GET request and tries to ensure the presence of
  Mako Web Server from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9357, 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9357 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(concl = egrep( string: banner, pattern: "Server: MakoServer\\.net", icase: TRUE )){
	concl = chomp( concl );
	version = "unknown";
	set_kb_item( name: "Mako/WebServer/installed", value: TRUE );
	cpe = "cpe:/a:mako:mako_web_server";
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Mako Web Server", version: version, install: "/", cpe: cpe, concluded: concl ), port: port );
	exit( 0 );
}
exit( 0 );

