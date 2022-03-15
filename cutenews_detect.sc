if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100105" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-05 20:39:41 +0200 (Sun, 05 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "CuteNews Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running CuteNews, a powerful and easy to use news management
system that uses flat files to store its database" );
	script_xref( name: "URL", value: "http://cutephp.com/cutenews/" );
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
for dir in nasl_make_list_unique( "/cutenews", "/utf-8", "/news", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	if( egrep( pattern: "Powered by <a [^>]+>CuteNews", string: buf, icase: TRUE ) || ContainsString( buf, "title>Please Login / CuteNews</title>" ) ){
		vers = "unknown";
		set_kb_item( name: "cutenews/installed", value: TRUE );
		version = eregmatch( string: buf, pattern: "Powered by <a [^>]+>CuteNews v*([0-9.]+)</a>", icase: TRUE );
		if( !isnull( version[1] ) ) {
			vers = version[1];
		}
		else {
			version = eregmatch( string: buf, pattern: ">CuteNews v\\.([0-9.]+)" );
			if(!isnull( version[1] )){
				vers = version[1];
			}
		}
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:cutephp:cutenews:" );
		if(!cpe){
			cpe = "cpe:/a:cutephp:cutenews";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "CuteNews", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
	else {
		if(ContainsString( buf, "<title>UTF-8 CuteNews</title>" )){
			set_kb_item( name: "cutenews/installed", value: TRUE );
			set_kb_item( name: "cutenews/utf-8", value: TRUE );
			version = eregmatch( string: buf, pattern: "UTF-8 CuteNews (([0-9.]+)([a-z]+)?)", icase: TRUE );
			if(!isnull( version[1] )){
				vers = version[1];
			}
			cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:cutephp:cutenews:" );
			if(!cpe){
				cpe = "cpe:/a:cutephp:cutenews";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "UTF-8 CuteNews", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
			exit( 0 );
		}
	}
}
exit( 0 );

