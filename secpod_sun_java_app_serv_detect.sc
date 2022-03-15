if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900200" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-06 06:53:35 +0100 (Fri, 06 Feb 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Sun Java System/ONE Application Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the Sun Java System/ONE Application Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( item: "/", port: port );
if(!res){
	exit( 0 );
}
vers = eregmatch( pattern: "Server: Sun[- a-zA-Z]+Application[- ]Server/?([a-zA-Z0-9._ ]+)", string: res );
if( vers[1] ){
	version = vers[1] - " Platform Edition ";
	version = chomp( version );
	found = TRUE;
}
else {
	if(egrep( pattern: "Sun Java System Application Server .*", string: res )){
		vers = eregmatch( pattern: "Platform Edition ([0-9.]+)", string: res );
		if(vers[1]){
			version = vers[1];
			found = TRUE;
		}
	}
}
if(found){
	set_kb_item( name: "sun_java_appserver/installed", value: TRUE );
	set_kb_item( name: "glassfish_or_sun_java_appserver/installed", value: TRUE );
	register_and_report_cpe( app: "Sun Java Application Server", ver: version, concluded: vers[0], base: "cpe:/a:sun:java_system_application_server:", expr: "^([0-9.]+)", insloc: "/", regService: "www" );
}
exit( 0 );

