if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100129" );
	script_version( "2021-07-12T14:00:54+0000" );
	script_tag( name: "last_modification", value: "2021-07-12 14:00:54 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Apache mod_perl Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "apache_server_info.sc", "apache_server_status.sc", "gb_apache_perl_status.sc", "gb_apache_http_server_http_error_page_detect.sc" );
	script_mandatory_keys( "mod_perl_or_apache_status_info_error_pages/banner" );
	script_xref( name: "URL", value: "https://perl.apache.org/" );
	script_tag( name: "summary", value: "HTTP based detection of Apache mod_perl." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
pattern = "^Server\\s*:.*mod_perl";
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
vers = eregmatch( string: found_banner, pattern: "Server\\s*:.*mod_perl/([0-9.]+)", icase: TRUE );
if(vers[1]){
	version = vers[1];
}
set_kb_item( name: "apache/mod_perl/detected", value: TRUE );
set_kb_item( name: "apache/mod_perl/http/detected", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:mod_perl:" );
if(!cpe){
	cpe = "cpe:/a:apache:mod_perl";
}
register_product( cpe: cpe, location: install, port: port, service: "www" );
log_message( data: build_detection_report( app: "Apache mod_perl", version: version, install: install, cpe: cpe, concludedUrl: conclurl, concluded: concluded ), port: port );
exit( 0 );

