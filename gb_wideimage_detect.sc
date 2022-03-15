if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805693" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-08-03 12:36:53 +0530 (Mon, 03 Aug 2015)" );
	script_name( "WideImage Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  WideImage.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
var installed;
for dir in nasl_make_list_unique( "/", "/WideImage-master", "/wideimage", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for url in make_list( "/index.php",
		 "/doc/index.html",
		 "/composer.json" ) {
		path = dir + url;
		rcvRes = http_get_cache( item: path, port: port );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ( ContainsString( rcvRes, "<title>WideImage" ) || IsMatchRegexp( rcvRes, "homepage.*wideimage" ) )){
			installed = TRUE;
			version = eregmatch( pattern: "(WideImage.v|((V|v)ersion.:..))([0-9.]+)", string: rcvRes );
			if( version[4] ){
				wideVersion = version[4];
			}
			else {
				continue;
			}
		}
	}
	if(installed){
		if(!wideVersion){
			wideVersion = "Unknown";
		}
		set_kb_item( name: "www/" + port + "/WideImage", value: wideVersion );
		set_kb_item( name: "WideImage/installed", value: TRUE );
		cpe = build_cpe( value: wideVersion, exp: "^([0-9.]+)", base: "cpe:/a:wideimage:wideimage:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:wideimage:wideimage";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "WideImage", version: wideVersion, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

