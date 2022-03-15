if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112807" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-12 10:32:22 +0000 (Wed, 12 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Laravel / Laravel Telescope Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8081, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Laravel and Laravel Telescope." );
	script_xref( name: "URL", value: "https://laravel.com/" );
	script_xref( name: "URL", value: "https://github.com/laravel/telescope" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8081 );
for dir in nasl_make_list_unique( "/", "/laravel", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	laravel_found = FALSE;
	telescope_found = FALSE;
	for file in make_list( "/telescope",
		 "/telescope/requests",
		 "/public/telescope",
		 "/" ) {
		url = dir + file;
		res = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			if(ContainsString( res, "<strong>Laravel</strong> Telescope" ) && ContainsString( res, "<div id=\"telescope\" v-cloak>" )){
				telescope_found = TRUE;
			}
			if(ContainsString( res, "<title>Laravel</title>" ) && ( ContainsString( res, "<div class=\"title m-b-md\">" ) || ContainsString( res, "window.Laravel = {\"csrfToken\"}" ) || ContainsString( res, "Set-Cookie: laravel_session" ) )){
				laravel_found = TRUE;
			}
			if(laravel_found || telescope_found){
				set_kb_item( name: "laravel/detected", value: TRUE );
				version = "unknown";
				register_and_report_cpe( app: "Laravel", ver: version, base: "cpe:/a:laravel:laravel:", expr: "([0-9.]+)", insloc: install, regService: "www", regPort: port );
				if(telescope_found){
					set_kb_item( name: "laravel/telescope/detected", value: TRUE );
					set_kb_item( name: "laravel/telescope/" + port + "/detected", value: TRUE );
					version = "unknown";
					register_and_report_cpe( app: "Laravel Telescope", ver: version, base: "cpe:/a:laravel:telescope:", expr: "([0-9.]+)", insloc: url, regService: "www", regPort: port );
				}
				exit( 0 );
			}
		}
	}
}
exit( 0 );

