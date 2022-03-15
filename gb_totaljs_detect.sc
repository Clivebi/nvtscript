if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142118" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-11 14:12:44 +0700 (Mon, 11 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Total.js Detection" );
	script_tag( name: "summary", value: "Detection of Total.js.

The script sends a connection request to the server and attempts to detect Total.js and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.totaljs.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(egrep( pattern: "X-Powered-By: total\\.js", string: banner, icase: TRUE )){
	version = "unknown";
	vers = eregmatch( pattern: "X-Powered-By: total\\.js v([0-9.]+)", string: banner, icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "totaljs/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:totaljs:total.js:" );
	if(!cpe){
		cpe = "cpe:/a:totaljs:total.js";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Total.js", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

