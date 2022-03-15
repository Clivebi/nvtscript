if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100274" );
	script_version( "2021-07-12T12:10:22+0000" );
	script_tag( name: "last_modification", value: "2021-07-12 12:10:22 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "nginx Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc", "gb_nginx_http_error_page_detect.sc", "gb_php_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of nginx." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
vers = "unknown";
if(banner && concl = egrep( pattern: "^Server\\s*:\\s*nginx", string: banner, icase: TRUE )){
	concl = chomp( concl );
	detected = TRUE;
	version = eregmatch( string: banner, pattern: "Server\\s*:\\s*nginx/([0-9.]+)", icase: TRUE );
	if( !isnull( version[1] ) ){
		vers = version[1];
	}
	else {
		host = http_host_name( dont_add_port: TRUE );
		phpList = http_get_kb_file_extensions( port: port, host: host, ext: "php" );
		if(phpList){
			phpFiles = make_list( phpList );
		}
		if( phpFiles[0] ) {
			url = phpFiles[0];
		}
		else {
			url = "/index.php";
		}
		banner = http_get_remote_headers( port: port, file: url );
		version = eregmatch( string: banner, pattern: "Server\\s*:\\s*nginx/([0-9.]+)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = version[1];
			if(concl){
				concl += "\n";
			}
			concl += version[0];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
}
if(!detected || vers == "unknown"){
	if(banner = get_kb_item( "www/nginx_error_page/banner/" + port )){
		vers = "unknown";
		detected = TRUE;
		if(url = get_kb_item( "www/nginx_error_page/banner/location/" + port )){
			if(conclUrl){
				conclUrl += "\n";
			}
			conclUrl += http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(concluded = get_kb_item( "www/nginx_error_page/banner/concluded/" + port )){
			if(concl){
				concl += "\n";
			}
			concl += concluded;
		}
		version = eregmatch( pattern: "Server\\s*:\\s*nginx/([0-9.]+)", string: banner, icase: TRUE );
		if( !isnull( version[1] ) ){
			vers = version[1];
			replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: nginx/" + vers );
		}
		else {
			replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: nginx" );
		}
	}
}
if(detected){
	install = port + "/tcp";
	for ngnx_status in make_list( "/",
		 "/basic_status",
		 "/nginx_status" ) {
		res = http_get_cache( port: port, item: ngnx_status );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( egrep( string: res, pattern: "^Active connections: [0-9]+" ) || egrep( string: res, pattern: "^server accepts handled requests( request_time)?" ) || egrep( string: res, pattern: "^Reading: [0-9]+ Writing: [0-9]+ Waiting: [0-9]+" ) )){
			extra = "- Output of the HttpStubStatusModule module available at " + http_report_vuln_url( port: port, url: ngnx_status, url_only: TRUE );
			break;
		}
	}
	set_kb_item( name: "nginx/detected", value: TRUE );
	set_kb_item( name: "nginx/http/detected", value: TRUE );
	set_kb_item( name: "nginx/http/port", value: port );
	set_kb_item( name: "nginx/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + vers + "#---#" + concl + "#---#" + conclUrl + "#---#" + extra );
}
exit( 0 );

