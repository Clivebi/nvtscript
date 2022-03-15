if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142516" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-06-28 05:59:08 +0000 (Fri, 28 Jun 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NetData Detection" );
	script_tag( name: "summary", value: "Detection of NetData.

  The script sends a connection request to the server and attempts to detect NetData and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80, 443, 8000 );
	script_mandatory_keys( "NetData/banner" );
	script_xref( name: "URL", value: "https://my-netdata.io/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8000 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "NetData Embedded HTTP Server" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "NetData Embedded HTTP Server v([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "netdata/detected", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:my-netdata:netdata:" );
if(!cpe){
	cpe = "cpe:/a:my-netdata:netdata";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "NetData", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

