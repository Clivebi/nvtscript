if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141868" );
	script_version( "2020-11-27T13:21:49+0000" );
	script_tag( name: "last_modification", value: "2020-11-27 13:21:49 +0000 (Fri, 27 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-01-11 14:27:25 +0700 (Fri, 11 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "TIBCO Spotfire Statistics Services Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of TIBCO Spotfire Statistics Services." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "HttpServer/banner" );
	script_require_ports( "Services/www", 8080 );
	script_xref( name: "URL", value: "https://www.tibco.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: HttpServer" )){
	exit( 0 );
}
url = "/";
res = http_get_cache( port: port, item: url );
if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) || !ContainsString( res, "Location: " )){
	exit( 0 );
}
dir = http_extract_location_from_redirect( port: port, data: res, current_dir: url );
if(isnull( dir )){
	exit( 0 );
}
res = http_get_cache( port: port, item: dir + "/" );
if(ContainsString( res, "Welcome to TIBCO Spotfire Statistics Services" ) && ContainsString( res, "alt=\"TIBCO Spotfire Statistics Services\"" )){
	version = "unknown";
	vers = eregmatch( pattern: "sf_statsvcs/([0-9.]+)/", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "tibco/spotfire_statistics_services/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:tibco:spotfire_statistics_services:" );
	if(!cpe){
		cpe = "cpe:/a:tibco:spotfire_statistics_services";
	}
	register_product( cpe: cpe, location: dir, port: port, service: "www" );
	log_message( data: build_detection_report( app: "TIBCO Spotfire Statistics Services", version: version, install: dir, cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

