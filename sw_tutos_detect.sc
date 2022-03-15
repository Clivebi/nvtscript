if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111040" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-10-07 14:00:00 +0200 (Wed, 07 Oct 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "TUTOS Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP
  request to the server and attempts to extract the version from
  the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
dirs = nasl_make_list_unique( "/", "/tutos", http_cgi_dirs( port: port ) );
for dir in dirs {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/php/mytutos.php", port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	buf2 = http_get_cache( item: dir + "/ChangeLog", port: port );
	if(ContainsString( buf, "<title>TUTOS" ) || ContainsString( buf2, "Please send all your feedback to gokohnert" )){
		version = "unknown";
		ver = eregmatch( pattern: "title=\"TUTOS ([0-9.]+)", string: buf );
		if( !isnull( ver[1] ) ){
			version = ver[1];
		}
		else {
			ver = eregmatch( pattern: "Release ([0-9.]+)", string: buf2 );
			if(!isnull( ver[1] )){
				version = ver[1];
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:tutos:tutos:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:tutos:tutos";
		}
		set_kb_item( name: "www/" + port + "/tutos", value: version );
		set_kb_item( name: "tutos/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "TUTOS", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

