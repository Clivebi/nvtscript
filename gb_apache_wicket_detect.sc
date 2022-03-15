if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807584" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-05-10 15:16:04 +0530 (Tue, 10 May 2016)" );
	script_name( "Apache Wicket Version Detection" );
	script_tag( name: "summary", value: "Detection of installed version
  of Apache Wicket.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/", "/wicket-examples", "/wicket/wicket-examples", "/apache-wicket", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.html", port: port );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ( ContainsString( rcvRes, "<title>Wicket Examples</title>" ) ) || ( ContainsString( rcvRes, "> Wicket" ) ) || ( ContainsString( rcvRes, "mappers\">Wicket" ) )){
		ver = eregmatch( pattern: "class=\"version\"> Wicket Version:.*>([0-9.A-Z-]+)</span>", string: rcvRes );
		if( ver[1] ){
			version = ver[1];
		}
		else {
			version = "unknown";
		}
		version = ereg_replace( pattern: "-", string: version, replace: "." );
		set_kb_item( name: "Apache/Wicket/Installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.A-Z]+)", base: "cpe:/a:apache:wicket:" );
		if(!cpe){
			cpe = "cpe:/a:apache:wicket";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Apache Wicket", version: version, install: install, cpe: cpe, concluded: version ), port: port );
	}
}
exit( 0 );

