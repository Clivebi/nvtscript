if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900256" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "FrontAccounting Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of FrontAccounting." );
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
for dir in nasl_make_list_unique( "/frontaccount", "/account", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( buf, "<title>FrontAccounting" ) || ContainsString( buf, "images/logo_frontaccounting.png" )){
		version = "unknown";
		ver = eregmatch( pattern: "(FrontAccounting |Version )([0-9.]+) ?([a-zA-Z]+ ?[0-9]+?)?", string: buf, icase: TRUE );
		if(!isnull( ver[2] )){
			if( ver[3] ){
				ver[3] = ereg_replace( string: ver[3], pattern: " ", replace: "" );
				version = ver[2] + "." + ver[3];
			}
			else {
				version = ver[2];
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/FrontAccounting", value: tmp_version );
		set_kb_item( name: "frontaccounting/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+) ?([a-zA-Z]+ ?[0-9]+?)?", base: "cpe:/a:frontaccounting:frontaccounting:" );
		if(!cpe){
			cpe = "cpe:/a:frontaccounting:frontaccounting";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "FrontAccounting", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

