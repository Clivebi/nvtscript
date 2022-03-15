if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100385" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-12-09 13:16:50 +0100 (Wed, 09 Dec 2009)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "RT: Request Tracker Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Request Tracker.

  This script sends an HTTP GET request and tries to get the version from the response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
for dir in nasl_make_list_unique( "/rt", "/tracker", http_cgi_dirs( port: http_port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.html";
	buf = http_get_cache( item: url, port: http_port );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "&#187;&#124;&#171; RT.*Best Practical Solutions, LLC", string: buf, icase: TRUE )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "&#187;&#124;&#171; RT ([0-9.]+)(rc[0-9]+)?", icase: TRUE );
		if( !isnull( version[1] ) && !isnull( version[2] ) ){
			vers = chomp( version[1] ) + "." + chomp( version[2] );
		}
		else {
			if(!isnull( version[1] ) && isnull( version[2] )){
				vers = chomp( version[1] );
			}
		}
		tmp_version = NASLString( vers, " under ", install );
		set_kb_item( name: NASLString( "www/", http_port, "/rt_tracker" ), value: tmp_version );
		set_kb_item( name: "RequestTracker/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:best_practical_solutions:request_tracker:" );
		if(!cpe){
			cpe = "cpe:/a:best_practical_solutions:request_tracker";
		}
		register_product( cpe: cpe, location: install, port: http_port, service: "www" );
		log_message( data: build_detection_report( app: "Request Tracker (RT)", version: vers, install: install, cpe: cpe, concluded: vers ), port: http_port );
	}
}

