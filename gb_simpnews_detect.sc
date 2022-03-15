if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801390" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-02 16:33:48 +0200 (Mon, 02 Aug 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SimpNews Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the running version of SimpNews." );
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
for dir in nasl_make_list_unique( "/SimpNews", "/simpnew248", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/news.php", port: port );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, ">SimpNews</" )){
		version = "unknown";
		ver = eregmatch( pattern: "> V([0-9.]+)", string: rcvRes );
		if( isnull( ver[1] ) ){
			sndReq = http_get( item: dir + "/admin/news.php", port: port );
			rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
			ver = eregmatch( pattern: "> V([0-9.]+)", string: rcvRes );
			if( isnull( ver[1] ) ){
				sndReq = http_get( item: dir + "/doc/version.txt", port: port );
				rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
				if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "Programmversion" )){
					ver = eregmatch( pattern: "([0-9.]+)", string: rcvRes );
					if(!isnull( ver[1] )){
						version = ver[1];
					}
				}
			}
			else {
				version = ver[1];
			}
		}
		else {
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/SimpNews", value: tmp_version );
		set_kb_item( name: "simpnews/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:boesch-it:simpnews:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:boesch-it:simpnews";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "SimpNews", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

