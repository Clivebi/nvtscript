if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100001" );
	script_version( "2021-07-22T08:27:04+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 08:27:04 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "osCommerce Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of osCommerce." );
	script_xref( name: "URL", value: "https://www.oscommerce.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/osc", "/oscommerce", "/store", "/catalog", "/shop", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(!res){
		continue;
	}
	if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( res, "osCsid=" ) && !egrep( string: res, pattern: "Powered by.+osCommerce", icase: FALSE ) )){
		url = dir + "/ssl_check.php";
		res = http_get_cache( item: url, port: port );
		if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) || !eregmatch( string: res, pattern: "SSL.+I[Dd].+SSL.+I[Dd]", icase: FALSE )){
			continue;
		}
	}
	version = "unknown";
	set_kb_item( name: "oscommerce/detected", value: TRUE );
	set_kb_item( name: "oscommerce/http/detected", value: TRUE );
	concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	cpe = "cpe:/a:oscommerce:oscommerce";
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "osCommerce", version: version, install: install, cpe: cpe, concludedUrl: concUrl ), port: port );
}
exit( 0 );

