if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103230" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-29 15:19:27 +0200 (Mon, 29 Aug 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "phpList Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running phpList, an open source email campaign manager." );
	script_xref( name: "URL", value: "http://www.phplist.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/admin", "/mail", "/list", http_cgi_dirs( port: port ) ) {
	found = FALSE;
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( port: port, item: url );
	if( egrep( pattern: "name=\"Powered-By\" content=\"phplist", string: buf, icase: TRUE ) ){
		found = TRUE;
	}
	else {
		url = dir + "/lists/admin/?page=about";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if( !egrep( pattern: "<meta name=\"Powered-By\" content=\"phplist", string: buf, icase: TRUE ) && !egrep( pattern: "phplist - about phplist", string: buf, icase: TRUE ) ) {
			continue;
		}
		else {
			found = TRUE;
		}
	}
	if(found){
		version = "unknown";
		vers = eregmatch( pattern: "name=\"Powered-By\" content=\"phplist version ([0-9.]+)\"", string: buf, icase: TRUE );
		if(isnull( vers[1] )){
			vers = eregmatch( string: buf, pattern: "phplist</a>, version ([0-9.]+)", icase: TRUE );
		}
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		set_kb_item( name: "phplist/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:phplist:phplist:" );
		if(!cpe){
			cpe = "cpe:/a:phplist:phplist";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "phpList", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

