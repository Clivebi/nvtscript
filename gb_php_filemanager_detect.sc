if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106033" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-07-29 10:33:31 +0700 (Wed, 29 Jul 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "PHP File Manager Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of PHP File Manager

  The script sends a connection request to the server and attempts to detect PHP File Manager." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/filemanager", "/fm", http_cgi_dirs( port: port ) ) {
	rep_dir = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(ContainsString( res, "php File Manager - Admin Control Panel" ) && ContainsString( res, "gfx/logo_FileManager.gif" )){
		vers = "unknown";
		set_kb_item( name: "www/" + port + "/phpfilemanager", value: vers );
		set_kb_item( name: "phpfilemanager/installed", value: TRUE );
		cpe = "cpe:/a:revived_wire_media:php_file_manager";
		register_product( cpe: cpe, location: rep_dir, port: port, service: "www" );
		log_message( data: build_detection_report( app: "PHP File Manager", version: vers, install: rep_dir, cpe: cpe ), port: port );
	}
}
exit( 0 );

