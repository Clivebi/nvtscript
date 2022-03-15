if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141147" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-06 13:57:48 +0700 (Wed, 06 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ABB Welcome IP-Gateway Detection" );
	script_tag( name: "summary", value: "Detection of ABB Welcome IP-Gateway.

The script sends a connection request to the server and attempts to detect ABB Welcome IP-Gateway and to extract
its firmware version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.busch-jaeger.de" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8081 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "cgi-bin/getinfo.cgi" ) && ContainsString( res, "For IP Gateway" )){
	version = "unknown";
	url = "/cgi-bin/getinfo.cgi?type=getversion";
	req = http_post( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "GW_V([0-9.]+)_[^;]+", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = url;
	}
	set_kb_item( name: "abb_ipgateway/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/h:abb:ip_gateway_firmware:" );
	if(!cpe){
		cpe = "cpe:/h:abb:ip_gateway_firmware";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "ABB Welcome IP-Gateway", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

