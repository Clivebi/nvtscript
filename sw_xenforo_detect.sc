if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111078" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-01-17 09:00:00 +0100 (Sun, 17 Jan 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "XenForo Forum Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://xenforo.com/" );
	script_tag( name: "summary", value: "This script detects an installed XenForo Forum." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/forum", "/forums", "/xenforo", "/xf", "/board", "/boards", http_cgi_dirs( port: port ) ) {
	found = FALSE;
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, ">Forum software by XenForo" ) || ContainsString( res, "jQuery.extend(true, XenForo," ) ) ){
		found = TRUE;
	}
	else {
		res = http_get_cache( item: dir + "/", port: port );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, ">Forum software by XenForo" ) || ContainsString( res, "jQuery.extend(true, XenForo," ) )){
			found = TRUE;
		}
	}
	if(found){
		ver = "unknown";
		set_kb_item( name: "www/can_host_tapatalk", value: TRUE );
		set_kb_item( name: "xenforo/detected", value: TRUE );
		cpe = "cpe:/a:xenforo:xenforo";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "XenForo", version: ver, install: install, cpe: cpe ), port: port );
	}
}
exit( 0 );

