if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808207" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-05-25 15:47:33 +0530 (Wed, 25 May 2016)" );
	script_name( "Pentaho Data Integration (PDI) Suite Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Pentaho Data Integration (PDI) Suite.

  This script sends an HTTP GET request and checks for the presence of
  Pentaho Data Integration (PDI) Suite from the response." );
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
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
penPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/pentaho", "/pentaho-di", "/pentaho-solutions", http_cgi_dirs( port: penPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/Login", port: penPort );
	rcvRes = http_send_recv( port: penPort, data: sndReq );
	if(ContainsString( rcvRes, "<title>Data Integration Server - Login</title>" ) && ContainsString( rcvRes, ">User Name" ) && ContainsString( rcvRes, ">Password" ) && ContainsString( rcvRes, "Pentaho Corporation" )){
		penVer = "Unknown";
		set_kb_item( name: "Pentaho/PDI/Suite/Installed", value: TRUE );
		cpe = "cpe:/a:pentaho:data_integration";
		register_product( cpe: cpe, location: install, port: penPort, service: "www" );
		log_message( data: build_detection_report( app: "Pentaho Data Integration (PDI) Suite", version: penVer, install: install, cpe: cpe, concluded: penVer ), port: penPort );
	}
}

