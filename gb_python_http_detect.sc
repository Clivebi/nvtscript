if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107020" );
	script_version( "2021-07-12T14:00:54+0000" );
	script_tag( name: "last_modification", value: "2021-07-12 14:00:54 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2016-07-04 19:31:49 +0200 (Mon, 04 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Python Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc", "apache_server_info.sc", "apache_server_status.sc", "gb_apache_perl_status.sc", "gb_apache_http_server_http_error_page_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "python_or_apache_status_info_error_pages/banner" );
	script_tag( name: "summary", value: "HTTP based detection of Python." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
pattern = "^Server\\s*:[^\r\n]*C?[^_]Python/[0-9.]+";
if( !banner || !found_banner = egrep( pattern: pattern, string: banner, icase: TRUE ) ){
	for infos in make_list( "server-info",
		 "server-status",
		 "perl-status",
		 "apache_error_page" ) {
		info = get_kb_item( "www/" + infos + "/banner/" + port );
		if(info && found_banner = egrep( pattern: pattern, string: info, icase: TRUE )){
			detected = TRUE;
			if( infos == "apache_error_page" ){
				url = get_kb_item( "www/apache_error_page/banner/location/" + port );
				if(!url){
					url = "";
				}
			}
			else {
				url = "/" + infos;
			}
			conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			concluded = get_kb_item( "www/" + infos + "/banner/concluded/" + port );
			break;
		}
	}
	if(!detected){
		exit( 0 );
	}
}
else {
	found_banner = chomp( found_banner );
	concluded = found_banner;
}
install = port + "/tcp";
vers = "unknown";
version = eregmatch( string: found_banner, pattern: "C?[^_]Python/([0-9.]+)", icase: TRUE );
if(!isnull( version[1] )){
	vers = version[1];
}
set_kb_item( name: "python/detected", value: TRUE );
set_kb_item( name: "python/http/detected", value: TRUE );
set_kb_item( name: "python/http/port", value: port );
set_kb_item( name: "python/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + vers + "#---#" + concluded + "#---#" + conclurl );
exit( 0 );

