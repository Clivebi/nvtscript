if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806612" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-06 12:02:52 +0530 (Fri, 06 Nov 2015)" );
	script_name( "Kallithea Remote Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 5000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  Kallithea.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 5000 );
for dir in nasl_make_list_unique( "/", "/kallithea", "/repos/kallithea", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/", port: port );
	if(IsMatchRegexp( rcvRes, "kallithea-scm.*>Kallithea<" ) && ContainsString( rcvRes, "kallithea.css" ) && ContainsString( rcvRes, "kallithea-logo" )){
		version = "unknown";
		if(ver = eregmatch( pattern: "target.*>Kallithea</a> ([0-9.]+)", string: rcvRes )){
			version = ver[1];
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: "kallithea\\.css\\?ver\\=([0-9.]+)", string: rcvRes );
			version = ver[1];
		}
		set_kb_item( name: "www/" + port + "/Kallithea", value: version );
		set_kb_item( name: "Kallithea/Installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kallithea:kallithea:" );
		if(!cpe){
			cpe = "cpe:/a:kallithea:kallithea";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Kallithea", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		exit( 0 );
	}
}

