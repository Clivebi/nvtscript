if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808205" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-05-24 17:56:31 +0530 (Tue, 24 May 2016)" );
	script_name( "Pentaho Business Analytics Suite Version Detection (HTTP)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Pentaho Business Analytics Suite.

  This script sends and HTTP GET request and checks for the presence of
  Pentaho Business Analytics Suite from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/", "/pentaho", "/pentaho-solutions", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/Login", port: port );
	if(ContainsString( res, "<title>Pentaho User Console - Login</title>" ) && ContainsString( res, ">User Name" ) && ContainsString( res, ">Password" ) && ContainsString( res, "Pentaho Corporation" )){
		version = "unknown";
		set_kb_item( name: "Pentaho/BA/Suite/Installed", value: TRUE );
		cpe = "cpe:/a:pentaho:business_analytics";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Pentaho Business Analytics (BA) Suite", version: version, install: install, cpe: cpe ), port: port );
	}
}
exit( 0 );

