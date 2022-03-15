if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811015" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-27 10:34:57 +0530 (Thu, 27 Apr 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Oracle E-Business Suite Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Oracle E-Business Suite Detection.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
oPort = http_get_port( default: 443 );
res = http_get_cache( port: oPort, item: "/" );
if(res && ContainsString( res, ">E-Business Suite Home Page Redirect<" ) && ContainsString( res, "The E-Business Home Page" )){
	set_kb_item( name: "Oracle/eBusiness/Suite/Installed", value: TRUE );
	oVer = "unknown";
	cpe = "cpe:/a:oracle:e-business_suite";
	register_product( cpe: cpe, location: "/", port: oPort, service: "www" );
	log_message( data: build_detection_report( app: "Oracle E-Business Suite", version: oVer, install: "/", cpe: cpe, concluded: oVer ), port: oPort );
}

