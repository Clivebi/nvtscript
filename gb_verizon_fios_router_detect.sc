if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142240" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-11 06:04:26 +0000 (Thu, 11 Apr 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Verizon Fios Router Detection" );
	script_tag( name: "summary", value: "Detection of Verizon Fios Routers.

The script sends a connection request to the server and attempts to detect Verizon Fios routers." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443, 8080, 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.verizon.com/home/accessories/fios-quantum-gateway/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8443 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>Verizon Router</title>" ) && ContainsString( res, "ng-app=\"vzui\"" )){
	version = "unknown";
	set_kb_item( name: "verizon/fios_router/detected", value: TRUE );
	cpe = "cpe:/h:verizon:fios_router";
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Verizon Fios Router", version: version, install: "/", cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

