if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900710" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Microsoft Internet Information Services (IIS) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Microsoft Internet Information Services (IIS)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
banner = http_get_remote_headers( port: port );
if(!banner || !IsMatchRegexp( banner, "^HTTP/1\\.[01] [0-9]{3}" )){
	exit( 0 );
}
detected = FALSE;
version = "unknown";
if(concl = egrep( string: banner, pattern: "^Server\\s*:\\s*(Microsoft-)?IIS", icase: TRUE )){
	concluded = chomp( concl );
	detected = TRUE;
	vers = eregmatch( pattern: "Server\\s*:\\s*(Microsoft-)?IIS/([0-9.]+)", string: concl, icase: TRUE );
	if(!isnull( vers[2] )){
		version = vers[2];
	}
}
if(!detected || version == "unknown"){
	check_urls = make_list( "/vt-test-non-existent.html",
		 "/vt-test/vt-test-non-existent.html" );
	asp_list = http_get_kb_file_extensions( port: port, host: host, ext: "asp*" );
	if(asp_list[0]){
		check_urls = make_list( check_urls,
			 asp_list[0] );
	}
	if(IsMatchRegexp( banner, "^HTTP/1\\.[01] 30[0-9]" )){
		loc = http_extract_location_from_redirect( port: port, data: banner, current_dir: "/" );
		if(loc){
			check_urls = make_list( check_urls,
				 loc );
		}
	}
	for check_url in check_urls {
		banner = http_get_remote_headers( port: port, file: check_url );
		if(!banner || !IsMatchRegexp( banner, "^HTTP/1\\.[01] [0-9]{3}" )){
			continue;
		}
		if(concl = egrep( string: banner, pattern: "^Server\\s*:\\s*(Microsoft-)?IIS", icase: TRUE )){
			detected = TRUE;
			vers = eregmatch( pattern: "Server\\s*:\\s*(Microsoft-)?IIS/([0-9.]+)", string: concl, icase: TRUE );
			if(!isnull( vers[2] )){
				if(concluded){
					concluded += "\n";
				}
				concluded += chomp( concl );
				concl_url = http_report_vuln_url( port: port, url: check_url, url_only: TRUE );
				version = vers[2];
			}
			break;
		}
	}
}
if(detected){
	install = port + "/tcp";
	set_kb_item( name: "IIS/installed", value: TRUE );
	replace_kb_item( name: "www/" + port + "/can_host_php", value: "yes" );
	replace_kb_item( name: "www/" + port + "/can_host_asp", value: "yes" );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:internet_information_services:" );
	if(!cpe){
		cpe = "cpe:/a:microsoft:internet_information_services";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Microsoft Internet Information Services (IIS)", version: version, install: install, cpe: cpe, concludedUrl: concl_url, concluded: concluded ), port: port );
}
exit( 0 );

