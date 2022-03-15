if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107220" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Zenbership CMS Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of Zenbership CMS.

  The script sends an HTTP request to the server and attempts to detect the application from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
appPort = http_get_port( default: 80 );
if(!http_can_host_php( port: appPort )){
	exit( 0 );
}
rootInstalled = FALSE;
for dir in nasl_make_list_unique( "/", "/zenbership", "/membership", "/member", "/zen", "/zenbership-master", http_cgi_dirs( port: appPort ) ) {
	if(rootInstalled){
		break;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin/login.php";
	rcvRes = http_get_cache( item: url, port: appPort );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "<title>Welcome to Zenbership" ) && ( ContainsString( rcvRes, "content=\"Zenbership Membership Software\"" ) || ContainsString( rcvRes, "a href=\"http://documentation.zenbership.com/\"" ) )){
		if(dir == ""){
			rootInstalled = TRUE;
		}
		vers = "unknown";
		tmpVer = eregmatch( pattern: ">v([0-9a-z]+)", string: rcvRes );
		if(tmpVer[1]){
			vers = tmpVer[1];
		}
		set_kb_item( name: "zenbership/installed", value: TRUE );
		set_kb_item( name: "zenbership/version", value: vers );
		cpe = build_cpe( value: vers, exp: "^([0-9a-z]+)", base: "cpe:/a:castlamp:zenbership:" );
		if(!cpe){
			cpe = "cpe:/a:castlamp:zenbership";
		}
		register_product( cpe: cpe, location: install, port: appPort, service: "www" );
		log_message( data: build_detection_report( app: "Zenbership", version: vers, install: install, cpe: cpe, concluded: tmpVer[0] ), port: appPort );
	}
}
exit( 0 );

