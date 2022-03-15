if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805642" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-03 12:12:21 +0530 (Wed, 03 Jun 2015)" );
	script_name( "NetCharts Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8001 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  Visual Mining NetCharts Server.

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
port = http_get_port( default: 8001 );
res = http_get_cache( item: "/Documentation/misc/about.jsp", port: port );
if(res && ContainsString( res, "NetCharts Server" ) && ContainsString( res, "Visual Mining" )){
	install = "/";
	version = "unknown";
	vers = eregmatch( pattern: "Version.*([0-9.]+).*&copy", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "netchart/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:visual_mining:netcharts_server:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:visual_mining:netcharts_server";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Visual Mining/NetChart", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
}
exit( 0 );

