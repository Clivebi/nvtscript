if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140683" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-01-15 14:18:25 +0700 (Mon, 15 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "yawcam Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of yawcam (Yet Another Webcam Software).

  The script sends a connection request to the server and attempts to detect yawcam and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80, 8081, 8888 );
	script_mandatory_keys( "yawcam/banner" );
	script_xref( name: "URL", value: "http://www.yawcam.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8081 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(!concl = egrep( string: banner, pattern: "yawcam", icase: FALSE )){
	exit( 0 );
}
set_kb_item( name: "yawcam/installed", value: TRUE );
concl = chomp( concl );
version = "unknown";
vers = eregmatch( pattern: "yawcam/([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	concl = vers[0];
}
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:yawcam:yawcam:" );
if(!cpe){
	cpe = "cpe:/a:yawcam:yawcam";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "yawcam", version: version, install: "/", cpe: cpe, concluded: concl ), port: port );
exit( 0 );

