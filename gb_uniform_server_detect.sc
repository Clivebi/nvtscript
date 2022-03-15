if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800786" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Uniform Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the installed Uniform Server version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
uniPort = http_get_port( default: 80 );
res = http_get_cache( item: "/", port: uniPort );
if(ContainsString( res, ">Uniform Server" )){
	version = "unknown";
	install = "/";
	ver = eregmatch( pattern: "Uniform Server (([0-9.]+).?([a-zA-Z]+))", string: res );
	if(ver[1] != NULL){
		version = ver[1];
	}
	set_kb_item( name: "www/" + uniPort + "/Uniform-Server", value: version );
	set_kb_item( name: "uniform-server/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:uniformserver:uniformserver:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:uniformserver:uniformserver";
	}
	register_product( cpe: cpe, location: install, port: uniPort, service: "www" );
	log_message( data: build_detection_report( app: "Uniform Server", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: uniPort );
}
exit( 0 );

