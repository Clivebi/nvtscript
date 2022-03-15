if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812366" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-28 10:46:29 +0530 (Thu, 28 Dec 2017)" );
	script_name( "Telesquare SKT LTE Router SDT-CS3B1 Detection" );
	script_tag( name: "summary", value: "Detection of Telesquare SKT LTE Router SDT-CS3B1.

  The script sends a connection request to the server and attempts to detect the
  presence of the router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
ltePort = http_get_port( default: 80 );
res = http_get_cache( port: ltePort, item: "/" );
if(ContainsString( res, "value='login'" ) && ContainsString( res, "<title>Login to SDT-CS3B1<" )){
	version = "unknown";
	install = ltePort + "/tcp";
	set_kb_item( name: "telesquare/SDT-CS3B1/detected", value: TRUE );
	cpe = "cpe:/h:telesquare:sdt-cs3b1";
	register_product( cpe: cpe, location: install, port: ltePort, service: "www" );
	log_message( data: build_detection_report( app: "Telesquare SKT LTE Router SDT-CS3B1", version: version, install: install, cpe: cpe, concluded: version ), port: ltePort );
	exit( 0 );
}
exit( 0 );

