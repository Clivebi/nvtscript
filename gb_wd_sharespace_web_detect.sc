if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812363" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-26 17:43:03 +0530 (Tue, 26 Dec 2017)" );
	script_name( "Western Digital ShareSpace WEB GUI Detect" );
	script_tag( name: "summary", value: "Detects the installed version of
  Western Digital ShareSpace.

  This script sends an HTTP GET request and tries to ensure the presence of
  Western Digital ShareSpace" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
wdPort = http_get_port( default: 80 );
rcvRes = http_get_cache( port: wdPort, item: "/" );
if(IsMatchRegexp( rcvRes, "<title>WD ShareSpace.*ShareSpace<" ) && IsMatchRegexp( rcvRes, "Copyright.*Western Digital Technologies" ) && ContainsString( rcvRes, ">Login<" )){
	version = "Unknown";
	set_kb_item( name: "WD/ShareSpace/detected", value: TRUE );
	cpe = "cpe:/a:western_digital:sharespace";
	location = "/";
	register_product( cpe: cpe, port: wdPort, location: location, service: "www" );
	log_message( data: build_detection_report( app: "Western Digital ShareSpace", version: version, install: location, cpe: cpe ), port: wdPort );
}
exit( 0 );

