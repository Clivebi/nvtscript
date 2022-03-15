if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108086" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-02-28 07:21:29 +0100 (Tue, 28 Feb 2017)" );
	script_name( "PayPal PHP Merchant SDK Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of the
  PayPal PHP Merchant SDK." );
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
for dir in nasl_make_list_unique( "/merchant-sdk-php", "/paypal", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/composer.json", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "\"name\": \"paypal/merchant-sdk-php\"," ) || ContainsString( res, "\"description\": \"PayPal Merchant SDK for PHP\"," ) )){
		version = "unknown";
		url = dir + "/CHANGELOG.md";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		vers = eregmatch( pattern: "####Version ([0-9.]+)", string: res );
		if( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && !isnull( vers[1] ) ){
			version = vers[1];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			url = dir + "/ChangeLog.txt";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			vers = eregmatch( pattern: "Version ([0-9.]+)", string: res );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && !isnull( vers[1] )){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		set_kb_item( name: "paypal/merchant-sdk-php/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:paypal:merchant-sdk-php:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:paypal:merchant-sdk-php";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "PayPal PHP Merchant SDK", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] ), port: port );
	}
}
exit( 0 );

