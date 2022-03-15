if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111009" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-26 12:00:00 +0100 (Thu, 26 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "RainLoop Webmail Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the server and attempts to extract the
  version from the reply." );
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
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/rainloop", "/webmail", "/mail", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/", port: port );
	manifest = eregmatch( pattern: "rel=\"manifest\" href=\"([^\"]+)", string: buf );
	if(!isnull( manifest[1] )){
		res = http_get_cache( port: port, item: dir + "/" + manifest[1] );
	}
	if(ContainsString( buf, "<meta name=\"Author\" content=\"RainLoop Team\" />" ) || ContainsString( res, "\"name\": \"RainLoop Webmail\"" )){
		version = "unknown";
		ver = eregmatch( pattern: "/v/([0-9.]+[0-9.]+[0-9.])/static", string: buf );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:rainloop:rainloop:" );
		if(!cpe){
			cpe = "cpe:/a:rainloop:rainloop";
		}
		set_kb_item( name: "rainloop/detected", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "RainLoop Webmail", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

