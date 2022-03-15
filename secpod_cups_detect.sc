if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900348" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_name( "CUPS Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 631 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of Common Unix Printing System (CUPS)

  This script sends an HTTP GET request and tries to get the version from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 631 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "Server: CUPS/" ) || IsMatchRegexp( res, "<TITLE>(Forbidden|Home|Not Found|Bad Request) - CUPS.*</TITLE>" )){
	version = "unknown";
	location = "/";
	ver = eregmatch( pattern: "<title>.*CUPS v?([0-9.RCB]+).*</title>", string: res, icase: TRUE );
	if( !isnull( ver[1] ) ){
		version = ver[1];
	}
	else {
		ver = eregmatch( pattern: "Server: CUPS/([0-9.RCB]+)", string: res, icase: TRUE );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
	}
	set_kb_item( name: "www/" + port + "/CUPS", value: version );
	set_kb_item( name: "CUPS/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)([a-z0-9]+)?", base: "cpe:/a:apple:cups:" );
	if(!cpe){
		cpe = "cpe:/a:apple:cups";
	}
	register_product( cpe: cpe, location: location, port: port, service: "www" );
	log_message( data: build_detection_report( app: "CUPS", version: version, install: location, port: port, cpe: cpe, concluded: ver[0] ), port: port );
}
exit( 0 );

