if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142810" );
	script_version( "2021-09-10T12:50:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:50:44 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-28 04:38:13 +0000 (Wed, 28 Aug 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "RICOH Printer Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of RICOH printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("ricoh_printers.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
urls = get_ricoh_detect_urls();
for url in keys( urls ) {
	model = "unknown";
	version = "unknown";
	pattern = urls[url];
	url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
	res = http_get_cache( item: url, port: port );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	match = eregmatch( pattern: pattern, string: res, icase: TRUE );
	if(!isnull( match[1] )){
		model = chomp( match[1] );
		concluded = "\n" + match[0];
		concludedUrl = "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		set_kb_item( name: "ricoh/printer/detected", value: TRUE );
		set_kb_item( name: "ricoh/printer/http/detected", value: TRUE );
		set_kb_item( name: "ricoh/printer/http/port", value: port );
		set_kb_item( name: "ricoh/printer/http/" + port + "/model", value: model );
		url = "/web/guest/en/websys/status/configuration.cgi";
		res = http_get_cache( port: port, item: url );
		vers = eregmatch( pattern: ">System<[^:]+:<[^<]+<td nowrap>([0-9.]+)", string: res );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			concluded += "\n" + vers[0];
			if(!ContainsString( concludedUrl, url )){
				concludedUrl += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		else {
			url = "/machinei.asp?Lang=en-us";
			res = http_get_cache( port: port, item: url );
			vers = eregmatch( pattern: "Firmware Version</td>[^V]+V([0-9.]+)", string: res );
			if(!isnull( vers[1] )){
				set_kb_item( name: "ricoh_printer/http/" + port + "/fw_version", value: vers[1] );
				concluded += "\n" + vers[0];
				if(!ContainsString( concludedUrl, url )){
					concludedUrl += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
		}
		set_kb_item( name: "ricoh/printer/http/" + port + "/concluded", value: concluded );
		set_kb_item( name: "ricoh/printer/http/" + port + "/concludedUrl", value: concludedUrl );
		set_kb_item( name: "ricoh/printer/http/" + port + "/fw_version", value: version );
		exit( 0 );
	}
}
exit( 0 );

