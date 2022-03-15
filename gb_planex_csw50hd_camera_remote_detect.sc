if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813895" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-09-06 16:25:25 +0530 (Thu, 06 Sep 2018)" );
	script_name( "PLANEX CS-W50HD Network Camera Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.planex.co.jp/products/cs-w50hd" );
	script_tag( name: "summary", value: "Detects whether the target is
  PLANEX CS-W50HD Network Camera.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
plxPort = http_get_port( default: 80 );
banner = http_get_remote_headers( port: plxPort );
if(!banner || !ContainsString( banner, "WWW-Authenticate: Basic realm=\"CS-W50HD\"" )){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "planex/csw50hd/installed", value: TRUE );
cpe = "cpe:/h:planex:ip_camera";
register_product( cpe: cpe, location: "/", port: plxPort, service: "www" );
log_message( data: build_detection_report( app: "PLANEX CS-W50HD Network Camera", version: version, install: "/", cpe: cpe, concluded: version ), port: plxPort );
exit( 0 );

