if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100845" );
	script_version( "2021-06-22T11:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-06-22 11:24:02 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "openEngine Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of openEngine, a Web Content Management
  System." );
	script_xref( name: "URL", value: "http://www.openengine.de" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/openengine", "/cms", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/cms/website.php?id=/de/index.htm&admin=login";
	buf = http_get_cache( item: url, port: port );
	if(egrep( pattern: "<title>openEngine", string: buf, icase: FALSE ) && egrep( pattern: "openEngine.+Open Source Web Content Management System", string: buf )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "openEngine ([0-9.]+)", icase: TRUE );
		if(version[1]){
			vers = version[1];
		}
		set_kb_item( name: "openengine/detected", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:openengine:openengine:" );
		if(!cpe){
			cpe = "cpe:/a:openengine:openengine";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "openEngine", version: vers, cpe: cpe, install: install, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

