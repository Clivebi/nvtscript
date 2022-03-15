if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117545" );
	script_version( "2021-07-12T12:10:22+0000" );
	script_tag( name: "last_modification", value: "2021-07-12 12:10:22 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-09 11:23:30 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "nginx Detection (HTTP Error Page)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP error-page based detection of nginx." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && egrep( string: banner, pattern: "^Server\\s*:\\s*nginx/[0-9.]+", icase: TRUE )){
	exit( 0 );
}
for url in make_list( "/",
	 "/vt-test-non-existent.html",
	 "/vt-test/vt-test-non-existent.html" ) {
	res = http_get_cache( port: port, item: url, fetch404: TRUE );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] [0-9]{3}" )){
		continue;
	}
	if(IsMatchRegexp( res, "<html>\\s*<head>\\s*<title>[^<]+</title>\\s*</head>\\s*<body" ) && IsMatchRegexp( res, "<hr>\\s*<center>nginx[^<]*</center>\\s*</body>\\s*</html>" )){
		set_kb_item( name: "nginx/error_page/detected", value: TRUE );
		set_kb_item( name: "www/nginx_error_page/banner/location/" + port, value: url );
		kb_banner = eregmatch( string: res, pattern: "<hr>\\s*<center>(nginx[^<]*)</center>", icase: FALSE );
		if(kb_banner[1]){
			set_kb_item( name: "www/nginx_error_page/banner/" + port, value: "Server: " + chomp( kb_banner[1] ) );
			set_kb_item( name: "www/nginx_error_page/banner/concluded/" + port, value: chomp( kb_banner[0] ) );
		}
		break;
	}
}
exit( 0 );

