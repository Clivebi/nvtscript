if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807549" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-19 11:50:28 +0530 (Tue, 19 Apr 2016)" );
	script_name( "ProjectSend Remote Version Detection" );
	script_tag( name: "summary", value: "Detection of ProjectSend web application.

  This script sends an HTTP GET request and checks for the presence of the
  application." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
pjtPort = http_get_port( default: 80 );
if(!http_can_host_php( port: pjtPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/ProjectSend", "/project", http_cgi_dirs( port: pjtPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	rcvRes = http_get_cache( item: url, port: pjtPort );
	if(IsMatchRegexp( rcvRes, "Provided by.*>ProjectSend.*Free software" ) && ContainsString( rcvRes, "<title>Log in" ) && ContainsString( rcvRes, ">Username" ) && ContainsString( rcvRes, ">Password" )){
		version = "unknown";
		set_kb_item( name: "www/" + pjtPort + install, value: version );
		set_kb_item( name: "ProjectSend/Installed", value: TRUE );
		cpe = "cpe:/a:projectsend:projectsend";
		register_product( cpe: cpe, location: install, port: pjtPort, service: "www" );
		log_message( data: build_detection_report( app: "ProjectSend", version: version, install: install, cpe: cpe, concluded: version ), port: pjtPort );
	}
}
exit( 0 );

