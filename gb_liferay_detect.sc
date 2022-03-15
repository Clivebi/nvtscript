if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808730" );
	script_version( "2021-08-05T10:00:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 10:00:50 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-08-01 13:52:04 +0530 (Mon, 01 Aug 2016)" );
	script_name( "Liferay Portal Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Liferay Portal." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.liferay.com/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", "/Liferay", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for url in nasl_make_list_unique( "/", "/web/guest" ) {
		url = dir + url;
		res = http_get_cache( port: port, item: url );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Liferay-Portal:" )){
			set_kb_item( name: "liferay/detected", value: TRUE );
			version = "unknown";
			vers = eregmatch( pattern: "Liferay-Portal: (Liferay ([a-zA-Z ]+)([0-9.]+)?)( (CE|EE|DE|DXP))?( ([GA0-9]+))?( \\(([a-zA-Z]+ / Build [0-9]+ / [a-zA-Z]+ [0-9]+, [0-9]+)\\))?", string: res );
			if(!isnull( vers[3] )){
				version = vers[3];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			if(!isnull( vers[7] )){
				version += "." + vers[7];
			}
			if(!isnull( vers[2] )){
				edition = chomp( vers[2] );
				set_kb_item( name: "liferay/" + port + "/edition", value: edition );
			}
			if(!isnull( vers[9] )){
				extra = "Build details: " + vers[9];
			}
			url = dir + "/api/jsonws";
			res = http_get_cache( port: port, item: url );
			if(res && ( ContainsString( res, "<title>json-web-services-api</title>" ) || ContainsString( res, "JSONWS API" ) )){
				if(extra){
					extra += "\n";
				}
				extra += "JSONWS API:    " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			if( IsMatchRegexp( edition, "^DXP" ) ){
				cpe = build_cpe( value: tolower( version ), exp: "([0-9.a-z]+)", base: "cpe:/a:liferay:dxp:" );
				if(!cpe){
					cpe = "cpe:/a:liferay:dxp";
				}
			}
			else {
				cpe = build_cpe( value: tolower( version ), exp: "([0-9.a-z]+)", base: "cpe:/a:liferay:liferay_portal:" );
				if(!cpe){
					cpe = "cpe:/a:liferay:liferay_portal";
				}
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Liferay " + edition, version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: conclUrl, extra: extra ), port: port );
			exit( 0 );
		}
	}
}
exit( 0 );

