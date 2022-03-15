if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807686" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-05-03 17:32:47 +0530 (Tue, 03 May 2016)" );
	script_name( "OpenWGA Content Management Server Version Detection" );
	script_tag( name: "summary", value: "Detection of installed version
  of OpenWGA Content Management Server.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
wgaPort = http_get_port( default: 8080 );
url = "/plugin-management/html/homepage:main.int.html";
req = http_get( item: url, port: wgaPort );
res = http_send_recv( port: wgaPort, data: req );
if(res && IsMatchRegexp( res, "OpenWG.*Server" ) && ContainsString( hexstr( res ), "4f70656e574741e284a220536572766572" ) && ContainsString( res, ">Web Content & Application Development Platform<" )){
	install = "/";
	version = eregmatch( pattern: "OpenWG.*Server ([0-9.]+) Maintenance Release .*Build ([0-9.]+)", string: res );
	if( version[1] && version[2] ){
		wgaVer = version[1] + "." + version[2];
	}
	else {
		wgaVer = "Unknown";
	}
	set_kb_item( name: "OpenWGA/Installed", value: TRUE );
	cpe = build_cpe( value: wgaVer, exp: "^([0-9.]+)", base: "cpe:/a:OpenWGA_CMS:openwga:" );
	if(!cpe){
		cpe = "cpe:/a:OpenWGA_CMS:openwga";
	}
	register_product( cpe: cpe, location: install, port: wgaPort, service: "www" );
	log_message( data: build_detection_report( app: "OpenWGA Content Manager", version: wgaVer, install: install, cpe: cpe, concluded: wgaVer ), port: wgaPort );
}

