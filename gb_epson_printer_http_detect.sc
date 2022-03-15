if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146411" );
	script_version( "2021-08-02T08:21:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-02 08:21:20 +0000 (Mon, 02 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-02 05:20:20 +0000 (Mon, 02 Aug 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Epson Printer Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Epson printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("epson_printers.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
urls = get_epson_detect_urls();
for url in keys( urls ) {
	pattern = urls[url];
	url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
	res = http_get_cache( port: port, item: url );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(match = eregmatch( pattern: pattern, string: res, icase: TRUE )){
		set_kb_item( name: "epson/printer/detected", value: TRUE );
		set_kb_item( name: "epson/printer/http/detected", value: TRUE );
		set_kb_item( name: "epson/printer/http/port", value: port );
		model = "unknown";
		fw_version = "unknown";
		if(!isnull( match[1] )){
			model = match[1];
			set_kb_item( name: "epson/printer/http/" + port + "/modConcluded", value: match[0] );
			set_kb_item( name: "epson/printer/http/" + port + "/modConcludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
		}
		url = "/PRESENTATION/ADVANCED/INFO_PRTINFO/TOP";
		res = http_get_cache( port: port, item: url );
		vers = eregmatch( pattern: "Firmware[^-]+[^>]+>([^<]+)<", string: res );
		if( !isnull( vers[1] ) ){
			fw_version = vers[1];
			set_kb_item( name: "epson/printer/http/" + port + "/versConcluded", value: vers[0] );
			set_kb_item( name: "epson/printer/http/" + port + "/versConcludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
		}
		else {
			url = "/iPrinterHome.cgi";
			res = http_get_cache( port: port, item: url );
			vers = eregmatch( pattern: "Main Version</td>[^>]+>\\s*([^<]+)<", string: res );
			if(!isnull( vers[1] )){
				fw_version = vers[1];
				set_kb_item( name: "epson/printer/http/" + port + "/versConcluded", value: vers[0] );
				set_kb_item( name: "epson/printer/http/" + port + "/versConcludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
			}
		}
		set_kb_item( name: "epson/printer/http/" + port + "/model", value: model );
		set_kb_item( name: "epson/printer/http/" + port + "/fw_version", value: fw_version );
		exit( 0 );
	}
}
res = http_get_remote_headers( port: port );
if(egrep( pattern: "SERVER\\s*:\\s*EPSON_Linux", string: res, icase: TRUE ) || egrep( pattern: "Epson UPnP SDK", string: res, icase: TRUE ) || egrep( pattern: "Server\\s*:\\s*EPSON HTTP Server", string: res, icase: TRUE ) || egrep( pattern: "Server\\s*:\\s*EPSON-HTTP", string: res, icase: TRUE )){
	set_kb_item( name: "epson/printer/detected", value: TRUE );
	set_kb_item( name: "epson/printer/http/detected", value: TRUE );
	set_kb_item( name: "epson/printer/http/port", value: port );
	model = "unknown";
	fw_version = "unknown";
	hw_version = "unknown";
	set_kb_item( name: "epson/printer/http/" + port + "/model", value: model );
	set_kb_item( name: "epson/printer/http/" + port + "/fw_version", value: fw_version );
	set_kb_item( name: "epson/printer/http/" + port + "/hw_version", value: hw_version );
}
exit( 0 );

