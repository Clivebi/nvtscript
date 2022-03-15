if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112034" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-09-04 12:33:04 +0200 (Mon, 04 Sep 2017)" );
	script_name( "Simple Online Planning Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of installed version
  of Simple Online Planning.

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
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/www", "/SOPlanning/www", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( port: port, item: dir + "/" );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ( ContainsString( rcvRes, "<title>SoPlanning</title>" ) || ContainsString( rcvRes, "<span class=\"soplanning_index_title2\">Simple Online Planning</span>" ) || ContainsString( rcvRes, "<a target=\"_blank\" href=\"http://www.soplanning.org\">www.soplanning.org</a>" ) || ContainsString( rcvRes, "<meta name=\"reply-to\" content=\"support@soplanning.org\" />" ) || ContainsString( rcvRes, "<meta name=\"email\" content=\"support@soplanning.org\" />" ) || ContainsString( rcvRes, "<meta name=\"Identifier-URL\" content=\"http://www.soplanning.org\" />" ) )){
		version = "unknown";
		set_kb_item( name: "soplanning/detected", value: TRUE );
		ver = eregmatch( pattern: "<small>v([0-9.]+)</small>", string: rcvRes );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:soplanning:soplanning:" );
		if(!cpe){
			cpe = "cpe:/a:soplanning:soplanning";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "SOPlanning", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

