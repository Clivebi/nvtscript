if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100106" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-05 20:39:41 +0200 (Sun, 05 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "phpMyFAQ Detection" );
	script_tag( name: "summary", value: "Detection of phpMyFAQ.

The script sends a connection request to the server and attempts to detect phpMyFAQ and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.phpmyfaq.de" );
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
for dir in nasl_make_list_unique( "/faq", "/phpmyfaq", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(egrep( pattern: "powered by phpMyFAQ", string: buf, icase: TRUE )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "phpMyFAQ ([0-9.]+).?([a-zA-Z0-9]+)?", icase: TRUE );
		if(!isnull( version[1] )){
			if( !isnull( version[2] ) ){
				vers = version[1] + "." + version[2];
			}
			else {
				vers = version[1];
			}
		}
		tmp_version = NASLString( vers, " under ", install );
		set_kb_item( name: NASLString( "www/", port, "/phpmyfaq" ), value: tmp_version );
		set_kb_item( name: "phpmyfaq/installed", value: TRUE );
		cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+)", base: "cpe:/a:phpmyfaq:phpmyfaq:" );
		if(!cpe){
			cpe = "cpe:/a:phpmyfaq:phpmyfaq";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "phpMyFAQ", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

