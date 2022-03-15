if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111026" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-08-21 14:00:00 +0200 (Fri, 21 Aug 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Icinga Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request
  to the server and attempts to detect the application from the reply." );
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
for dir in nasl_make_list_unique( "/", "/icinga", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/main.html", port: port );
	req2 = http_get( item: dir + "/cgi-bin/config.cgi", port: port );
	buf2 = http_keepalive_send_recv( port: port, data: req2 );
	if(eregmatch( pattern: "<title>Icinga</title>", string: buf, icase: TRUE ) || ContainsString( buf, "Icinga Development Team" ) || eregmatch( pattern: "<title>Configuration</title>", string: buf2, icase: TRUE ) || ContainsString( buf2, "Icinga Development Team" )){
		version = "unknown";
		ver = eregmatch( pattern: "version\">Version ([0-9.]+)</div>", string: buf, icase: TRUE );
		if( !isnull( ver[1] ) ){
			version = ver[1];
		}
		else {
			ver = eregmatch( pattern: "\\(Backend <b>([0-9.]+)</b>\\)", string: buf2, icase: TRUE );
			if(!isnull( ver[1] )){
				version = ver[1];
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:icinga:icinga:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:icinga:icinga";
		}
		set_kb_item( name: "www/" + port + "/icinga", value: version );
		set_kb_item( name: "icinga/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Icinga", version: version, concluded: ver[0], install: install, cpe: cpe ), port: port );
	}
}
exit( 0 );

