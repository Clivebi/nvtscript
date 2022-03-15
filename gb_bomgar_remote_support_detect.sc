if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805199" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-22 16:44:50 +0530 (Mon, 22 Jun 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Bomgar Remote Support Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Bomgar Remote Support.

  This script sends an HTTP GET request and tries to confirm the application from
  the response and get the version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
require("cpe.inc.sc");
require("host_details.inc.sc");
http_port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/bomgar", http_cgi_dirs( port: http_port ) ) {
	rep_dir = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/" ), port: http_port );
	if(ContainsString( rcvRes, "Bomgar Corporation" ) && ContainsString( rcvRes, "Support Portal" )){
		bomgarVer = eregmatch( pattern: "Version: ([0-9.]+)", string: rcvRes );
		if( bomgarVer[1] ){
			version = bomgarVer[1];
		}
		else {
			version = "Unknown";
		}
		set_kb_item( name: "Bomgar/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:bomgar:remote_support:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:bomgar:remote_support";
		}
		register_product( cpe: cpe, location: dir, port: http_port, service: "www" );
		log_message( data: build_detection_report( app: "Bomgar Remote Support", version: version, install: rep_dir, cpe: cpe, concluded: bomgarVer[0] ), port: http_port );
	}
}
exit( 0 );

