if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105951" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-02-06 14:11:41 +0700 (Fri, 06 Feb 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Gogs (Go Git Service) Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to detect
Gogs and to extract its version." );
	script_xref( name: "URL", value: "https://gogs.io/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 3000 );
for dir in nasl_make_list_unique( "/", "/gogs", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/user/login";
	res = http_get_cache( item: url, port: port );
	if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(ContainsString( res, "<title>Sign In - Gogs" ) || ( ContainsString( res, "Gogs" ) && ContainsString( res, "i_like_gogits" ) )){
		version = "unknown";
		ver = eregmatch( string: res, pattern: "GoGits.*Version: ([0-9.]+)" );
		if( !isnull( ver[1] ) ){
			version = ver[1];
		}
		else {
			ver = eregmatch( string: res, pattern: "Gogs Version: ([0-9.]+)" );
			if(!isnull( ver[1] )){
				version = ver[1];
			}
		}
		set_kb_item( name: "gogs/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:gogs:gogs:" );
		if(!cpe){
			cpe = "cpe:/a:gogs:gogs";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Gogs (Go Git Service)", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		goVersion = "unknown";
		goVer = eregmatch( string: res, pattern: "version\">Go([0-9.]+)" );
		if(!isnull( goVer[1] )){
			goVersion = goVer[1];
		}
		cpe = build_cpe( value: goVersion, exp: "^([0-9.]+)", base: "cpe:/a:golang:go:" );
		if(!cpe){
			cpe = "cpe:/a:golang:go";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Go Programming Language", version: goVersion, install: install, cpe: cpe, concluded: goVer[0] ), port: port );
	}
}
exit( 0 );

