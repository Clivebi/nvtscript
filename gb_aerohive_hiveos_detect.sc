if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106875" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-06-16 11:44:13 +0700 (Fri, 16 Jun 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Aerohive Networks HiveOS Detection" );
	script_tag( name: "summary", value: "Detection of Aerohive Networks HiveOS.

The script sends a connection request to the server and attempts to detect Aerohive Networks HiveOS and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.aerohive.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/index.php5" );
if(( ContainsString( res, "<title>Aerohive NetConfig UI</title>" ) || ContainsString( res, "<title>Aerohive HiveUI</title>" ) ) && ContainsString( res, "><b>Hive</b>OS</td>" )){
	version = "unknown";
	vers = eregmatch( pattern: "version=([0-9r.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "aerohive_hiveos/version", value: version );
	}
	set_kb_item( name: "aerohive_hiveos/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9r.]+)", base: "cpe:/o:aerohive:hiveos:" );
	if(!cpe){
		cpe = "cpe:/o:aerohive:hiveos";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	os_register_and_report( os: "Aerohive Networks HiveOS", cpe: cpe, port: port, banner_type: "HTTP login page", desc: "Aerohive Networks HiveOS Detection", runs_key: "unixoide" );
	log_message( data: build_detection_report( app: "Aerohive Networks HiveOS", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

