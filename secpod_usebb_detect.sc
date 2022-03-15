if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901056" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "UseBB Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed UseBB version." );
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
for dir in nasl_make_list_unique( "/", "/UseBB", "/usebb", "/forum", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ( ContainsString( rcvRes, "<a href=\"http://www.usebb.net\">UseBB 1 Forum Software</a>" ) || ContainsString( rcvRes, "content=\"forum,board,community,usebb\"" ) )){
		version = "unknown";
		sndReq = http_get( item: dir + "/Changelog.txt", port: port );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		ver = eregmatch( pattern: "UseBB (([0-9.]+)( ?(beta|RC|a|b)( ?[0-9]+)?)?)", string: rcvRes );
		ver[1] = ereg_replace( pattern: " ", string: ver[1], replace: "." );
		if(ver[1] != NULL){
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/UseBB", value: tmp_version );
		set_kb_item( name: "usebb/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)\\.([0-9a-zA-Z.]+)", base: "cpe:/a:usebb:usebb:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:usebb:usebb";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "UseBB", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );
