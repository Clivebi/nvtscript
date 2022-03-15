if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100926" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-12-01 14:30:53 +0100 (Wed, 01 Dec 2010)" );
	script_name( "Pandora FMS Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract
  the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://pandorafms.org" );
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
for dir in nasl_make_list_unique( "/", "/pandora_console", "/fms", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( buf, "<title>Pandora FMS -" )){
		version = "unknown";
		ver = eregmatch( string: buf, pattern: "ver_num\">v[0-9.]+NG\\.([0-9]+)<" );
		if( !isnull( ver[1] ) ){
			version = ver[1];
		}
		else {
			ver = eregmatch( string: buf, pattern: ">v([0-9.]+(SP[0-9]+)?( Build [a-zA-Z0-9]+)?)", icase: TRUE );
			if(!isnull( ver[1] )){
				version = chomp( ver[1] );
			}
		}
		set_kb_item( name: "pandora_fms/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9A-Za-z. ]+)", base: "cpe:/a:artica:pandora_fms:" );
		if(!cpe){
			cpe = "cpe:/a:artica:pandora_fms";
		}
		cpe = str_replace( string: cpe, find: " ", replace: "_" );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Pandora FMS", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

