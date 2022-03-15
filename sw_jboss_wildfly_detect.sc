if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111036" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-09-07 12:00:00 +0200 (Mon, 07 Sep 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "JBoss WildFly Application Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP
  request to the server and attempts to identify a JBoss WildFly Application Server
  and its version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if( concluded = eregmatch( string: banner, pattern: "Server: WildFly[ /]?([0-9.]?)", icase: TRUE ) ){
	installed = TRUE;
}
else {
	buf = http_get_cache( item: "/", port: port );
	if( concluded = eregmatch( string: buf, pattern: "Welcome to WildFly ([0-9.]?)" ) ){
		installed = TRUE;
	}
	else {
		buf = http_get_cache( item: "/documentation.html", port: port );
		if(concluded = eregmatch( string: buf, pattern: "WildFly ([0-9.]?) Documentation" )){
			installed = TRUE;
		}
	}
}
if(installed){
	set_kb_item( name: "JBoss/WildFly/installed", value: TRUE );
	cpe = build_cpe( value: concluded[1], exp: "^([0-9.]+)", base: "cpe:/a:redhat:jboss_wildfly_application_server:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:redhat:jboss_wildfly_application_server";
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "www" );
	log_message( data: build_detection_report( app: "JBoss WildFly Application Server", version: concluded[1], install: port + "/tcp", cpe: cpe, concluded: concluded[0] ), port: port );
}
exit( 0 );

