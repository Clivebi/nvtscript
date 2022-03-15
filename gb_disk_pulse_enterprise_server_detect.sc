if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809056" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-05 16:17:52 +0530 (Wed, 05 Oct 2016)" );
	script_name( "Disk Pulse Enterprise Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  Disk Pulse Enterprise Server.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
diskPort = http_get_port( default: 80 );
res = http_get_cache( item: "/login", port: diskPort );
if(ContainsString( res, "Disk Pulse Enterprise Login" ) && ContainsString( res, ">User Name" ) && ContainsString( res, ">Password" )){
	install = "/";
	diskVer = "unknown";
	vers = eregmatch( pattern: ">Disk Pulse Enterprise v([0-9.]+)", string: res );
	if(vers[1]){
		diskVer = vers[1];
	}
	set_kb_item( name: "DiskPulse/Enterprise/Server/installed", value: TRUE );
	cpe = build_cpe( value: diskVer, exp: "([0-9.]+)", base: "cpe:/a:diskpulse:diskpulse_enterprise_web_server:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:diskpulse:diskpulse_enterprise_web_server";
	}
	register_product( cpe: cpe, location: install, port: diskPort, service: "www" );
	log_message( data: build_detection_report( app: "Disk Pulse Enterprise Server", version: diskVer, install: install, cpe: cpe, concluded: vers[0] ), port: diskPort );
}
exit( 0 );

