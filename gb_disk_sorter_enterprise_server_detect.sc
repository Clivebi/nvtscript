if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810300" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-06 10:26:00 +0530 (Tue, 06 Dec 2016)" );
	script_name( "Disk Sorter Enterprise Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  Disk Sorter Enterprise Server.

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
sorterPort = http_get_port( default: 80 );
res = http_get_cache( item: "/login", port: sorterPort );
if(ContainsString( res, "Disk Sorter Enterprise Login" ) && ContainsString( res, ">User Name" ) && ContainsString( res, ">Password" )){
	install = "/";
	sorterVer = "unknown";
	vers = eregmatch( pattern: ">Disk Sorter Enterprise v([0-9.]+)", string: res );
	if(vers[1]){
		sorterVer = vers[1];
	}
	set_kb_item( name: "DiskSorter/Enterprise/Server/installed", value: TRUE );
	cpe = build_cpe( value: sorterVer, exp: "([0-9.]+)", base: "cpe:/a:disksorter:disksorter_enterprise_web_server:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:disksorter:disksorter_enterprise_web_server";
	}
	register_product( cpe: cpe, location: install, port: sorterPort, service: "www" );
	log_message( data: build_detection_report( app: "Disk Sorter Enterprise Server", version: sorterVer, install: install, cpe: cpe, concluded: vers[0] ), port: sorterPort );
}
exit( 0 );

