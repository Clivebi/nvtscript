if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806723" );
	script_version( "2021-07-19T12:32:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-19 12:32:02 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-11-24 16:05:56 +0530 (Tue, 24 Nov 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenSSL Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc", "apache_server_info.sc", "apache_server_status.sc", "gb_apache_perl_status.sc", "gb_apache_http_server_http_error_page_detect.sc" );
	script_mandatory_keys( "openssl_or_apache_status_info_error_pages/banner" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "summary", value: "HTTP based detection of OpenSSL." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
pattern = "^Server\\s*:.*OpenSSL";
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
version = "unknown";
vers = eregmatch( pattern: "Server\\s*:.*OpenSSL/([0-9.a-z]+)", string: found_banner, icase: TRUE );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "openssl/detected", value: TRUE );
set_kb_item( name: "openssl_or_gnutls/detected", value: TRUE );
set_kb_item( name: "openssl/http/detected", value: TRUE );
set_kb_item( name: "openssl/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + concluded + "#---##---#" + conclurl );
exit( 0 );

