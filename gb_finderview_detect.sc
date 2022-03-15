if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808096" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-27 13:22:53 +0530 (Mon, 27 Jun 2016)" );
	script_name( "FinderView Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  FinderView.

  This script sends an HTTP GET request and tries to ensure the presence of FinderView
  from the response." );
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
find_port = http_get_port( default: 80 );
if(!http_can_host_php( port: find_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/FinderView-master", "/FinderView", http_cgi_dirs( port: find_port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.html";
	rcvRes = http_get_cache( item: url, port: find_port );
	if(ContainsString( rcvRes, ">Finder View<" ) && IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "<th>Folder<" )){
		version = "unknown";
		set_kb_item( name: "FinderView/Installed", value: TRUE );
		cpe = "cpe:/a:finderview:finderview";
		register_product( cpe: cpe, location: install, port: find_port, service: "www" );
		log_message( data: build_detection_report( app: "FinderView", version: version, install: install, cpe: cpe, concluded: version ), port: find_port );
		exit( 0 );
	}
}

