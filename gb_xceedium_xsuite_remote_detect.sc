if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807087" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-03 18:23:52 +0530 (Thu, 03 Mar 2016)" );
	script_name( "Xceedium Xsuite Remote Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of installed version
  of Xceedium Xsuite.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( rcvRes, "<title>Xceedium Xsuite" ) && ContainsString( rcvRes, "User:" ) && ContainsString( rcvRes, "Password:" )){
		version = "unknown";
		set_kb_item( name: "www/" + port + "/Xceedium Xsuite", value: version );
		set_kb_item( name: "Xceedium/Xsuite/Installed", value: TRUE );
		cpe = "cpe:/a:xceedium:xsuite";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Xceedium Xsuite", version: version, install: install, cpe: cpe ), port: port );
	}
}
exit( 0 );
