if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113692" );
	script_version( "2021-05-27T07:09:59+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 07:09:59 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2020-05-20 12:00:00 +0200 (Wed, 20 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cherokee Web Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the Cherokee Web Server." );
	script_xref( name: "URL", value: "https://cherokee-project.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && concl = egrep( string: banner, pattern: "^Server\\s*:\\s*Cherokee", icase: TRUE )){
	concluded = chomp( concl );
	version = "unknown";
	detected = TRUE;
	vers = eregmatch( string: banner, pattern: "Server\\s*:\\s*Cherokee/([0-9.]+)", icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
}
if(!version || version == "unknown"){
	for url in make_list( "/",
		 "/vt-test-non-existent.html",
		 "/vt-test/vt-test-non-existent.html" ) {
		res = http_get_cache( item: url, port: port, fetch404: TRUE );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] [3-5][0-9]{2}" )){
			if(concl = egrep( string: res, pattern: "Cherokee web server.*, Port [0-9]+", icase: FALSE )){
				version = "unknown";
				detected = TRUE;
				conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				concl = chomp( concl );
				if(concluded){
					concluded += "\n";
				}
				concluded += concl;
				vers = eregmatch( pattern: "Cherokee web server ([0-9.]+)", string: concl, icase: FALSE );
				if( !isnull( vers[1] ) ){
					version = vers[1];
					replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: Cherokee/" + version );
				}
				else {
					replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: Cherokee" );
				}
				break;
			}
		}
	}
}
if(detected){
	set_kb_item( name: "cherokee/detected", value: TRUE );
	set_kb_item( name: "cherokee/http/detected", value: TRUE );
	register_and_report_cpe( app: "Cherokee Web Server", ver: version, concluded: concluded, base: "cpe:/a:cherokee-project:cherokee:", expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www", conclUrl: conclurl );
}
exit( 0 );

