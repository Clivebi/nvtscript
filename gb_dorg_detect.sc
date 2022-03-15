if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806696" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-06 16:24:58 +0530 (Wed, 06 Apr 2016)" );
	script_name( "Disc Organization System (DORG) Remote Version Detection" );
	script_tag( name: "summary", value: "Detection of Disc Organization System (DORG).

  This script sends an HTTP GET request and checks for the presence of
  the application." );
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
dorgPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/dorg", http_cgi_dirs( port: dorgPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin_panel/index.php";
	dorgRes = http_get_cache( port: dorgPort, item: url );
	if(IsMatchRegexp( dorgRes, "<title>DORG.*admin panel<" ) && ContainsString( dorgRes, ">Disc Organization System<" )){
		version = "unknown";
		set_kb_item( name: "www/" + dorgPort + "/dorg", value: version );
		set_kb_item( name: "DORG/Installed", value: TRUE );
		cpe = "cpe:/a:dorg:dorg";
		register_product( cpe: cpe, location: install, port: dorgPort, service: "www" );
		log_message( data: build_detection_report( app: "Disc Organization System - DORG", version: version, install: install, cpe: cpe, concluded: version ), port: dorgPort );
	}
}
exit( 0 );

