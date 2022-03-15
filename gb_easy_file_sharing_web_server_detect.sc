if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806517" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-05 11:28:37 +0530 (Thu, 05 Nov 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Easy File Sharing Web Server Detection (HTTP)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Easy File Sharing Web Server.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "EasyFileSharingWebServer/banner" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(concl = egrep( string: banner, pattern: "Server: Easy File Sharing Web Server", icase: TRUE )){
	version = "unknown";
	concl = chomp( concl );
	vers = eregmatch( pattern: "Server: Easy File Sharing Web Server v([0-9.]+)", string: banner );
	if(vers[1]){
		version = vers[1];
		concl = vers[0];
	}
	set_kb_item( name: "www/" + port + "/", value: version );
	set_kb_item( name: "Easy/File/Sharing/WebServer/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:efssoft:easy_file_sharing_web_server:" );
	if(!cpe){
		cpe = "cpe:/a:efssoft:easy_file_sharing_web_server";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Easy File Sharing Web Server", version: version, install: "/", cpe: cpe, concluded: concl ), port: port );
}
exit( 0 );

