if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117544" );
	script_version( "2021-07-19T12:32:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-19 12:32:02 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-09 09:17:42 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Apache HTTP Server Detection (HTTP Error Page)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP error-page based detection of the Apache HTTP Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && egrep( string: banner, pattern: "^Server\\s*:\\s*Apache/[0-9.]+", icase: TRUE )){
	exit( 0 );
}
pattern1 = "<address>(.+) Server at .+ Port [0-9]+</address>";
pattern2 = "\\s*<span>(Apache[^<]*)</span>";
for url in make_list( "/",
	 "/vt-test-non-existent.html",
	 "/vt-test/vt-test-non-existent.html" ) {
	res = http_get_cache( item: url, port: port, fetch404: TRUE );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] [3-5][0-9]{2}" )){
		continue;
	}
	if( concl = egrep( string: res, pattern: "^" + pattern1, icase: TRUE ) ){
		error_page_found = TRUE;
		kb_banner = eregmatch( string: concl, pattern: pattern1, icase: TRUE );
	}
	else {
		if(IsMatchRegexp( res, "<address>.*<a href=.+</a>.*<span>Apache[^<]*</span>.*</address>" )){
			error_page_found = TRUE;
			concl = egrep( string: res, pattern: "^" + pattern2, icase: TRUE );
			if(concl){
				kb_banner = eregmatch( string: concl, pattern: pattern2, icase: TRUE );
			}
		}
	}
	if(error_page_found){
		set_kb_item( name: "apache/http_server/error_page/detected", value: TRUE );
		set_kb_item( name: "www/apache_error_page/banner/location/" + port, value: url );
		set_kb_item( name: "mod_jk_or_apache_status_info_error_pages/banner", value: TRUE );
		set_kb_item( name: "mod_perl_or_apache_status_info_error_pages/banner", value: TRUE );
		set_kb_item( name: "mod_python_or_apache_status_info_error_pages/banner", value: TRUE );
		set_kb_item( name: "mod_ssl_or_apache_status_info_error_pages/banner", value: TRUE );
		set_kb_item( name: "openssl_or_apache_status_info_error_pages/banner", value: TRUE );
		set_kb_item( name: "perl_or_apache_status_info_error_pages/banner", value: TRUE );
		set_kb_item( name: "python_or_apache_status_info_error_pages/banner", value: TRUE );
		if(kb_banner[1]){
			set_kb_item( name: "www/apache_error_page/banner/" + port, value: "Server: " + chomp( kb_banner[1] ) );
			concluded = chomp( kb_banner[0] );
			if(ContainsString( concluded, " Server at " ) && !ContainsString( concluded, "Apache" )){
				concluded += " (Note: This is an Apache HTTP Server error page with a modified server banner)";
			}
			set_kb_item( name: "www/apache_error_page/banner/concluded/" + port, value: concluded );
		}
		break;
	}
}
exit( 0 );

