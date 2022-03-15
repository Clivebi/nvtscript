if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100136" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "WebFileExplorer Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.webfileexplorer.com/" );
	script_tag( name: "summary", value: "This host is running WebFileExplorer, a web based file management
  system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/fileexplorer", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/", port: port );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "<title>WebFileExplorer.*</title>", string: buf, icase: TRUE ) && egrep( pattern: "Set-Cookie: fileoptions.*", string: buf, icase: TRUE )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "<title>WebFileExplorer v([0-9.]+)</title>", icase: TRUE );
		if(!isnull( version[1] )){
			vers = version[1];
		}
		set_kb_item( name: "webfileexplorer/detected", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:webfileexplorer:web_file_explorer:" );
		if(!cpe){
			cpe = "cpe:/a:webfileexplorer:web_file_explorer";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "WebFileExplorer", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

