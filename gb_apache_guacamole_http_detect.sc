if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144235" );
	script_version( "2021-08-04T11:10:17+0000" );
	script_tag( name: "last_modification", value: "2021-08-04 11:10:17 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-07-15 03:40:31 +0000 (Wed, 15 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Guacamole Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Apache Guacamole." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://guacamole.apache.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/guacamole", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/" );
	if(!res){
		continue;
	}
	if(ContainsString( res, "<title>Guacamole" ) || ContainsString( res, "images/guacamole-logo-64.png" ) || ContainsString( res, "guac-ui.js" ) || ContainsString( res, "<guac-notification notification" )){
		version = "unknown";
		vers = eregmatch( pattern: "<div id=\"version\">\\s+Guacamole ([0-9.]+)", string: res );
		if( !isnull( vers[1] ) ){
			version = vers[1];
		}
		else {
			vers = eregmatch( pattern: "\\.js\\?v=([0-9.]+)", string: res );
			if(!isnull( vers[1] )){
				version = vers[1];
			}
		}
		set_kb_item( name: "apache/guacamole/detected", value: TRUE );
		set_kb_item( name: "apache/guacamole/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:guacamole:" );
		if(!cpe){
			cpe = "cpe:/a:apache:guacamole";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Apache Guacamole", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

