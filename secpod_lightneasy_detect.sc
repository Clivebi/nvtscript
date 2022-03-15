if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900371" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "LightNEasy Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of LightNEasy." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/lne", "/lightneasy", "/nodatabase", "/sqlite", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/LightNEasy.php?do=login", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	rcvRes2 = http_get_cache( item: dir + "/index.php", port: port );
	if(( IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ( ContainsString( rcvRes, "generator' content='LightNEasy" ) || ContainsString( rcvRes, "LightNEasy.php?page=index" ) || ContainsString( rcvRes, "css/lightneasy.css" ) ) ) || ( IsMatchRegexp( rcvRes2, "^HTTP/1\\.[01] 200" ) && ( ContainsString( rcvRes2, "generator' content='LightNEasy" ) || ContainsString( rcvRes2, "LightNEasy.php?do=login" ) || ContainsString( rcvRes2, "css/lightneasy.css" ) ) )){
		version = "unknown";
		ver = eregmatch( pattern: "LightNEasy ([0-9.]+)", string: rcvRes );
		if( ver[1] != NULL ){
			version = ver[1];
		}
		else {
			ver = eregmatch( pattern: "LightNEasy( Mini)? ([0-9.]+)", string: rcvRes2 );
			if(ver[2] != NULL){
				version = ver[2];
			}
		}
		set_kb_item( name: "lightneasy/detected", value: TRUE );
		tmp_version = version + " under " + install;
		if( ContainsString( rcvRes, "SQLite" ) || ContainsString( rcvRes, "sqlite" ) ){
			set_kb_item( name: "www/" + port + "/LightNEasy/Sqlite", value: tmp_version );
			cpe = "cpe:/a:sqlite:sqlite";
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "SQLite", install: install, cpe: cpe ), port: port );
		}
		else {
			set_kb_item( name: "www/" + port + "/LightNEasy/NoDB", value: tmp_version );
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:lightneasy:lightneasy:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:lightneasy:lightneasy";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "LightNEasy", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

