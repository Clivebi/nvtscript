if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809334" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-06 14:17:14 +0530 (Thu, 06 Oct 2016)" );
	script_name( "ZKTeco ZKBioSecurity Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  ZKTeco ZKBioSecurity.

  This script sends an HTTP GET request and tries to ensure the presence of
  ZKTeco ZKBioSecurity." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8088 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
zktPort = http_get_port( default: 8088 );
res = http_get_cache( item: "/", port: zktPort );
if(ContainsString( res, "<title>ZKBioSecurity</title>" ) && ContainsString( res, "password" )){
	install = "/";
	version = "unknown";
	set_kb_item( name: "ZKTeco/ZKBioSecurity/Installed", value: TRUE );
	cpe = "cpe:/a:zkteco:zkbiosecurity";
	register_product( cpe: cpe, location: install, port: zktPort, service: "www" );
	log_message( data: build_detection_report( app: "ZKteco ZKBioSecurity", version: version, install: install, cpe: cpe, concluded: version ), port: zktPort );
}
exit( 0 );

