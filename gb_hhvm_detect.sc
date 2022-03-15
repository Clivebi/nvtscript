if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105140" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-12-09 14:29:24 +0100 (Tue, 09 Dec 2014)" );
	script_name( "HHVM Detection" );
	script_xref( name: "URL", value: "http://hhvm.com/" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract
  the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "HHVM/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "X-Powered-By: HHVM/" )){
	exit( 0 );
}
vers = "unknown";
version = eregmatch( pattern: "X-Powered-By: HHVM/([^ \r\n]+)", string: banner );
if(!isnull( version[1] )){
	vers = version[1];
}
set_kb_item( name: "HHVM/detected", value: TRUE );
cpe = build_cpe( value: vers, exp: "^([0-9.]+.*)$", base: "cpe:/a:facebook:hhvm:" );
if(!cpe){
	cpe = "cpe:/a:facebook:hhvm";
}
register_product( cpe: cpe, location: port + "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "HHVM", version: vers, install: "/", cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

