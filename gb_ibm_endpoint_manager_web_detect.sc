if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105128" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-12-03 13:24:33 +0100 (Wed, 03 Dec 2014)" );
	script_name( "IBM Endpoint Manager Web Detection (HTTP)" );
	script_tag( name: "summary", value: "The script sends a connection
  request to the server and attempts to extract the version number
  from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 52311 );
	script_mandatory_keys( "BigFixHTTPServer/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 52311 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(!concl = egrep( string: banner, pattern: "Server: BigFixHTTPServer", icase: TRUE )){
	exit( 0 );
}
concl = chomp( concl );
version = "unknown";
vers = eregmatch( pattern: "BigFixHTTPServer/([^ \r\n]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	concl = vers[0];
	set_kb_item( name: "ibm_endpoint_manager/version", value: version );
}
set_kb_item( name: "ibm_endpoint_manager/installed", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:tivoli_endpoint_manager:" );
if(!cpe){
	cpe = "cpe:/a:ibm:tivoli_endpoint_manager";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "IBM Endpoint Manager", version: version, install: "/", cpe: cpe, concluded: concl ), port: port );
exit( 0 );

