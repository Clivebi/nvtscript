if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807537" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-12 10:34:57 +0530 (Tue, 12 Apr 2016)" );
	script_name( "Novell Service Desk Remote Version Detection" );
	script_tag( name: "summary", value: "Detection of installed version
  of Novell Service Desk.

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
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
novPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/novell", "/novell-service-desk", http_cgi_dirs( port: novPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/LiveTime/WebObjects/LiveTime.woa" ), port: novPort );
	rcvRes = http_send_recv( port: novPort, data: sndReq );
	if(ContainsString( rcvRes, "Licensee: Novell" ) && IsMatchRegexp( rcvRes, "content=\".*Service Management and Service Desk" ) && ContainsString( rcvRes, "username" ) && ContainsString( rcvRes, "password" )){
		version = eregmatch( pattern: ">Version #([0-9.]+)", string: rcvRes );
		if( version[1] ){
			novellVer = version[1];
		}
		else {
			novellVer = "Unknown";
		}
		set_kb_item( name: "Novell/Service/Desk/Installed", value: TRUE );
		cpe = build_cpe( value: novellVer, exp: "^([0-9.]+)", base: "cpe:/a:novell:service_desk:" );
		if(!cpe){
			cpe = "cpe:/a:novell:service_desk";
		}
		register_product( cpe: cpe, location: install, port: novPort, service: "www" );
		log_message( data: build_detection_report( app: "Novell Service Desk", version: novellVer, install: install, cpe: cpe, concluded: novellVer ), port: novPort );
	}
}

