if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808219" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-09 13:45:38 +0530 (Thu, 09 Jun 2016)" );
	script_name( "Moxa EDR G903 Router Remote Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Moxa EDR G903 Router.

  This script sends an HTTP GET request and checks for the presence of Moxa EDR G903
  Router from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
edrPort = http_get_port( default: 80 );
if(!http_can_host_asp( port: edrPort )){
	exit( 0 );
}
url = "/Login.asp";
res = http_get_cache( item: url, port: edrPort );
if(ContainsString( res, "<TITLE>Moxa EDR</TITLE>" ) && ContainsString( res, "Moxa EtherDevice Secure Router" ) && ContainsString( res, "Username :" ) && ContainsString( res, "Password :" ) && ( ContainsString( res, "ProjectModel = 1" ) || ContainsString( res, ">EDR-G903<" ) )){
	edrVer = "Unknown";
	set_kb_item( name: "Moxa/EDR/G903/Installed", value: TRUE );
	cpe = "cpe:/h:moxa:edr-g903";
	register_product( cpe: cpe, location: "/", port: edrPort, service: "www" );
	log_message( data: build_detection_report( app: "Moxa EDR G903 Router", version: edrVer, install: "/", cpe: cpe, concluded: edrVer ), port: edrPort );
}

