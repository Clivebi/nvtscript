if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100190" );
	script_version( "2021-03-01T15:58:40+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 15:58:40 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Oracle / Eclipse GlassFish Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080, 8181, 4848 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Oracle / Eclipse GlassFish Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
buf = http_get_cache( item: "/index.html", port: port );
buf2 = http_get_cache( item: "/vt-test-non-existent.html", port: port, fetch404: TRUE );
if(( ContainsString( buf, "<title>GlassFish Server" ) && ContainsString( buf, "Server Running</title>" ) ) || egrep( pattern: "Server:.*GlassFish.*", string: buf, icase: TRUE ) || ( ContainsString( buf2, "<title>GlassFish Server" ) && ContainsString( buf2, "Error report</title>" ) ) || ContainsString( buf, "Log In to GlassFish Administration Console" )){
	vers = "unknown";
	version = eregmatch( string: buf, pattern: "Server:.*GlassFish[^0-9]+v([0-9.]+)", icase: TRUE );
	if( isnull( version[1] ) ){
		version = eregmatch( string: buf, pattern: "GlassFish Server( Open Source Edition)?( )? ([0-9.]+)", icase: TRUE );
		if( !isnull( version[3] ) ){
			vers = version[3];
		}
		else {
			version = eregmatch( string: buf2, pattern: "GlassFish Server( Open Source Edition)?( )? ([0-9.]+)", icase: TRUE );
			if(!isnull( version[3] )){
				vers = version[3];
			}
		}
	}
	else {
		vers = version[1];
	}
	if(egrep( pattern: "Location:.*login.jsf", string: buf ) || ( egrep( pattern: "Log In to.*GlassFish", string: buf ) && ContainsString( buf, "<title>Login" ) )){
		report = "The GlassFish Administration Console is running at this port.";
		set_kb_item( name: "www/" + port + "/GlassFishAdminConsole", value: TRUE );
		set_kb_item( name: "GlassFishAdminConsole/port", value: port );
	}
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:oracle:glassfish_server:" );
	if(!cpe){
		cpe = "cpe:/a:oracle:glassfish_server";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	set_kb_item( name: "GlassFish/installed", value: TRUE );
	set_kb_item( name: "glassfish_or_sun_java_appserver/installed", value: TRUE );
	log_message( data: build_detection_report( app: "Oracle / Eclipse GlassFish Server", version: vers, install: "/", cpe: cpe, concluded: version[0], extra: report ), port: port );
}
exit( 0 );

