if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900498" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Apache HTTP Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc", "apache_server_info.sc", "apache_server_status.sc", "gb_apache_perl_status.sc", "gb_apache_http_server_http_error_page_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the Apache HTTP Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
base_pattern = "^Server\\s*:\\s(Apache(-AdvancedExtranetServer)?($|/)|Rapidsite/Apa)";
version_pattern = "(Apache(-AdvancedExtranetServer)?/|Rapidsite/Apa-)([0-9.]+(-(alpha|beta))?)";
server_banner = egrep( pattern: "^Server\\s*:.+apa", string: banner, icase: TRUE );
if(server_banner){
	server_banner = chomp( server_banner );
}
if(server_banner && concl = egrep( string: server_banner, pattern: base_pattern, icase: TRUE )){
	concluded = chomp( concl );
	version = "unknown";
	detected = TRUE;
	vers = eregmatch( pattern: "Server\\s*:\\s*" + version_pattern, string: server_banner, icase: TRUE );
	if(!isnull( vers[3] )){
		version = vers[3];
	}
}
if(!version || version == "unknown"){
	for infos in make_list( "server-info",
		 "server-status",
		 "perl-status" ) {
		info = get_kb_item( "www/" + infos + "/banner/" + port );
		if(info){
			version = "unknown";
			detected = TRUE;
			conclurl = http_report_vuln_url( port: port, url: "/" + infos, url_only: TRUE );
			info = chomp( info );
			if(concluded){
				concluded += "\n";
			}
			concluded += info;
			vers = eregmatch( pattern: "Server\\s*:\\s*" + version_pattern, string: info, icase: TRUE );
			if( !isnull( vers[3] ) ){
				version = vers[3];
				replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: " + vers[1] + version );
			}
			else {
				replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: Apache" );
			}
			break;
		}
	}
}
if(!version || version == "unknown"){
	if(concl = get_kb_item( "www/apache_error_page/banner/" + port )){
		version = "unknown";
		detected = TRUE;
		if(url = get_kb_item( "www/apache_error_page/banner/location/" + port )){
			if(conclurl){
				conclurl += "\n";
			}
			conclurl += http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		concl = chomp( concl );
		if(concluded){
			concluded += "\n";
		}
		concluded += concl;
		vers = eregmatch( pattern: "Server\\s*:\\s*" + version_pattern, string: concl, icase: TRUE );
		if( !isnull( vers[3] ) ){
			version = vers[3];
			replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: " + vers[1] + version );
		}
		else {
			replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: Apache" );
		}
	}
}
if(!version || version == "unknown"){
	for url in make_list( "/manual/en/index.html",
		 "/" ) {
		res = http_get_cache( item: url, port: port );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Documentation - Apache HTTP Server" ) && concl = egrep( string: res, pattern: "<title>Apache HTTP Server Version", icase: TRUE )){
			version = "unknown";
			detected = TRUE;
			if(conclurl){
				conclurl += "\n";
			}
			conclurl += http_report_vuln_url( port: port, url: url, url_only: TRUE );
			concl = chomp( concl );
			if(concluded){
				concluded += "\n";
			}
			concluded += concl;
			vers = eregmatch( pattern: "<title>Apache HTTP Server Version ([0-9.]+)", string: concl );
			if( !isnull( vers[1] ) ){
				version = vers[1];
				replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: Apache/" + version );
			}
			else {
				replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: Apache" );
			}
			break;
		}
	}
}
if(detected){
	set_kb_item( name: "apache/http_server/detected", value: TRUE );
	set_kb_item( name: "apache/http_server/http/detected", value: TRUE );
	set_kb_item( name: "apache/http_server/http/" + port + "/installs", value: port + "#---#" + port + "/tcp" + "#---#" + version + "#---#" + concluded + "#---#" + conclurl + "#---#" );
}
exit( 0 );

