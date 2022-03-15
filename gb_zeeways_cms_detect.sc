if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808107" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-03 17:28:29 +0530 (Fri, 03 Jun 2016)" );
	script_name( "Zeeways CMS Remote Detection" );
	script_tag( name: "summary", value: "Detection of Zeeways CMS.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
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
zeePort = http_get_port( default: 80 );
if(!http_can_host_php( port: zeePort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/zeeways", "/cms", http_cgi_dirs( port: zeePort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/admin/index.php", port: zeePort );
	if(ContainsString( rcvRes, "<title>ZeewaysCMS - Admin Login</title>" ) && ContainsString( rcvRes, "Username" ) && ContainsString( rcvRes, "Password" )){
		version = "unknown";
		set_kb_item( name: "ZeewaysCMS/Installed", value: TRUE );
		cpe = "cpe:/a:zeewayscms:zeeway";
		register_product( cpe: cpe, location: install, port: zeePort, service: "www" );
		log_message( data: build_detection_report( app: "ZeewaysCMS", version: version, install: install, cpe: cpe, concluded: version ), port: zeePort );
		exit( 0 );
	}
}
exit( 0 );

