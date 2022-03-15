if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140785" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-16 13:00:31 +0700 (Fri, 16 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Schneider Electric StruxureOn Gateway Detection" );
	script_tag( name: "summary", value: "Detection of Schneider Electric StruxureOn Gateway.

The script sends a connection request to the server and attempts to detect Schneider Electric StruxureOn Gateway
and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://struxureon.com//" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/dce/rest/settings/version";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "StruxureOn Gateway" )){
	version = "unknown";
	vers = eregmatch( pattern: "\"version\" : \"([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "struxureon/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:schneider_electric:struxureon_gateway:" );
	if(!cpe){
		cpe = "cpe:/a:schneider_electric:struxureon_gateway";
	}
	register_product( cpe: cpe, location: "/dce", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Schneider Electric StuxureOn Gateway", version: version, install: "/dce", cpe: cpe, concluded: vers[0], concludedUrl: url ), port: port );
	exit( 0 );
}
exit( 0 );

