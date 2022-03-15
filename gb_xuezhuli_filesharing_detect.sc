if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808175" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-27 14:54:44 +0530 (Mon, 27 Jun 2016)" );
	script_name( "XuezhuLi FileSharing Detection" );
	script_tag( name: "summary", value: "Detection of installed version
  of XuezhuLi FileSharing.

  This script sends an HTTP GET request and tries to check the presence of
  XuezhuLi FileSharing from the response." );
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
file_Port = http_get_port( default: 80 );
if(!http_can_host_php( port: file_Port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/FileSharing-master", "/FileSharing", http_cgi_dirs( port: file_Port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: file_Port );
	if(ContainsString( rcvRes, "<title>File Manager</title>" ) && ContainsString( rcvRes, "Username" ) && ContainsString( rcvRes, ">login<" ) && ContainsString( rcvRes, ">signup<" )){
		version = "unknown";
		set_kb_item( name: "www/" + file_Port + install, value: version );
		set_kb_item( name: "XuezhuLi/FileSharing/Installed", value: TRUE );
		cpe = "cpe:/a:xuezhuLi:xuezhuli_filesharing";
		register_product( cpe: cpe, location: install, port: file_Port, service: "www" );
		log_message( data: build_detection_report( app: "XuezhuLi FileSharing", version: version, install: install, cpe: cpe, concluded: version ), port: file_Port );
	}
}
exit( 0 );

