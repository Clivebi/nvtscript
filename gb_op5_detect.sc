if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103379" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-09 10:33:57 +0100 (Mon, 09 Jan 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OP5 Monitor Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of op5 Monitor

The script sends a connection request to the server and attempts to detect the presence of op5 Monitor and to
extract its version" );
	script_xref( name: "URL", value: "https://www.op5.com/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/", port: port );
if(egrep( pattern: "Welcome to op5 portal", string: buf, icase: TRUE )){
	version = "unknown";
	vers = eregmatch( string: buf, pattern: "Version: *([0-9.]+) *\\| *<a +href=\".*/monitor\"" );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "op5/version", value: version );
	}
	set_kb_item( name: "OP5/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:op5:monitor:" );
	if(!cpe){
		cpe = "cpe:/a:op5:monitor";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "OP5 Monitor", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

