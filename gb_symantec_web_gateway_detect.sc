if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103483" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-05-04 17:35:57 +0200 (Fri, 04 May 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Symantec Web Gateway Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Symantec Web Gateway.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
symPort = http_get_port( default: 80 );
if(!http_can_host_php( port: symPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: symPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/spywall/login.php" );
	req = http_get( item: url, port: symPort );
	buf = http_keepalive_send_recv( port: symPort, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "<title>Symantec Web Gateway - Login", string: buf, icase: TRUE )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: ">(Version ([0-9.]+))<", icase: TRUE );
		if(!isnull( version[2] )){
			vers = chomp( version[2] );
		}
		set_kb_item( name: NASLString( "www/", symPort, "/symantec_web_gateway" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "symantec_web_gateway/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:symantec:web_gateway:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:symantec:web_gateway";
		}
		register_product( cpe: cpe, location: install, port: symPort, service: "www" );
		log_message( data: build_detection_report( app: "Symantec Web Gateway", version: vers, install: install, cpe: cpe, concluded: version[1] ), port: symPort );
	}
}
exit( 0 );

