if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107300" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-15 14:47:17 +0100 (Thu, 15 Feb 2018)" );
	script_name( "TrendNet Router Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to detect the
  presence of the router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
trdPort = http_get_port( default: 8080 );
res = http_get_cache( port: trdPort, item: "/" );
if(ContainsString( res, "Login to the" ) && ( ContainsString( res, "<title>TRENDNET | WIRELESS N ROUTER </title>" ) || ContainsString( res, "<title>TRENDNET | WIRELESS N GIGABIT ROUTER </title>" ) )){
	model = "unknown";
	version = "unknown";
	install = trdPort + "/tcp";
	router = eregmatch( pattern: "Server: Linux, HTTP/1.., (TEW-[0-9a-zA-Z]+) Ver ([0-9.]+)", string: res );
	if(!isnull( router[1] )){
		model = router[1];
	}
	if(!isnull( router[2] )){
		version = router[2];
	}
	set_kb_item( name: "trendnet/detected", value: TRUE );
	set_kb_item( name: "trendnet/model", value: model );
	set_kb_item( name: "trendnet/version", value: version );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/h:trendnet:" + tolower( model ) + ":" );
	if(!cpe){
		cpe = "cpe:/h:trendnet:" + tolower( model );
	}
	register_product( cpe: cpe, location: install, port: trdPort, service: "www" );
	log_message( data: build_detection_report( app: "TrendNet Router " + model, version: version, install: install, cpe: cpe, concluded: router ), port: trdPort );
	exit( 0 );
}
exit( 0 );

