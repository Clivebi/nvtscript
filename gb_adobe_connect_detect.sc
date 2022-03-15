if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805661" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-19 10:58:10 +0530 (Fri, 19 Jun 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Adobe Connect Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe Connect.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: NASLString( "/system/login" ), port: port );
if(ContainsString( res, "Adobe Connect Central Login" ) && IsMatchRegexp( res, "Copyright.*Adobe Systems" )){
	acVer = eregmatch( pattern: "class=\"loginHelp\" title=\"([0-9.]+)", string: res );
	if( !acVer[1] ){
		acVer = "Unknown";
	}
	else {
		acVer = acVer[1];
	}
	set_kb_item( name: "www/" + port + "/", value: acVer );
	set_kb_item( name: "adobe/connect/installed", value: TRUE );
	cpe = build_cpe( value: acVer, exp: "([0-9.]+)", base: "cpe:/a:adobe:connect:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:adobe:connect";
	}
	register_product( cpe: cpe, location: NASLString( "/system/login" ), port: port, service: "www" );
	log_message( data: build_detection_report( app: "Adobe Connect", version: acVer, install: NASLString( "/system/login" ), cpe: cpe, concluded: acVer ), port: port );
}

