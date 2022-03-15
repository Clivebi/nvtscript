if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808217" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-06 15:55:57 +0530 (Mon, 06 Jun 2016)" );
	script_name( "Dolphin Version Detection" );
	script_tag( name: "summary", value: "Check for the presence of Dolphin
  Software.

  This script sends an HTTP GET request and tries to ensure the presence of Dolphin
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
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
dol_port = http_get_port( default: 80 );
if(!http_can_host_php( port: dol_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/dolph", "/dolphin", http_cgi_dirs( port: dol_port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/administration/profiles.php";
	sndReq = http_get( item: url, port: dol_port );
	rcvRes = http_send_recv( port: dol_port, data: sndReq );
	if(ContainsString( rcvRes, "Dolphin" ) && ContainsString( rcvRes, "boonex" ) && ContainsString( rcvRes, "<title>Login</title>" ) && ContainsString( rcvRes, "id=\"admin_username\"" ) && ContainsString( rcvRes, "id=\"admin_password\"" )){
		version = "unknown";
		set_kb_item( name: "Dolphin/Installed", value: TRUE );
		cpe = "cpe:/a:boonex:dolphin";
		register_product( cpe: cpe, location: install, port: dol_port, service: "www" );
		log_message( data: build_detection_report( app: "Dolphin", version: version, install: install, cpe: cpe ), port: dol_port );
	}
}
exit( 0 );

