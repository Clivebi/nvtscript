if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900381" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Mahara Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of Mahara." );
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
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/mahara", "/", "/mahara/htdocs", "/htdocs", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(!ContainsString( res, "Welcome to Mahara" )){
		url = dir + "/admin/index.php";
		res = http_get_cache( item: url, port: port );
	}
	if(ContainsString( res, "Log in to Mahara" ) || ContainsString( res, "Welcome to Mahara" ) || ContainsString( res, "content=\"Mahara" )){
		set_kb_item( name: "mahara/detected", value: TRUE );
		version = "unknown";
		for file in make_list( "/Changelog",
			 "/ChangeLog",
			 "/debian/Changelog" ) {
			url2 = dir + file;
			res2 = http_get_cache( item: url2, port: port );
			if(ContainsString( res2, "mahara" )){
				ver = egrep( pattern: "([0-9.]+[0-9.]+[0-9]+ \\([0-9]{4}-[0-9]{2}-[0-9]{2}\\))", string: res2 );
				ver = eregmatch( pattern: "^(mahara\\ )?\\(?(([0-9.]+[0-9.]+[0-9]+)(\\~" + "(beta|alpha)([0-9]))?\\-?([0-9])?)\\)?([^0-9]" + "|$)", string: ver );
				ver = ereg_replace( pattern: NASLString( "[~|-]" ), replace: NASLString( "." ), string: ver[2] );
			}
			if(!isnull( ver )){
				version = ver;
				concUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
				break;
			}
		}
		if(version == "unknown"){
			url2 = dir + "/lib/version.php.temp";
			req = http_get( port: port, item: url2 );
			res2 = http_keepalive_send_recv( port: port, data: req );
			ver = eregmatch( pattern: "config->release = '([0-9.]+)", string: res2 );
			if( !isnull( ver[1] ) ){
				version = ver[1];
				concUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
			}
			else {
				ver = eregmatch( pattern: "content=\"Mahara ([0-9.]+)", string: res );
				if(!isnull( ver[1] )){
					version = ver[1];
					concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+\\.[0-9.])\\.?([a-z0-9]+)?", base: "cpe:/a:mahara:mahara:" );
		if(!cpe){
			cpe = "cpe:/a:mahara:mahara";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Mahara", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concUrl ), port: port );
	}
}
exit( 0 );

