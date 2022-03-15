if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142906" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-18 03:01:18 +0000 (Wed, 18 Sep 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Toshiba Printer Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Toshiba printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("toshiba_printers.inc.sc");
port = http_get_port( default: 8080 );
urls = get_toshiba_detect_urls();
for url in keys( urls ) {
	pattern = urls[url];
	url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
	res = http_get_cache( port: port, item: url );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(match = eregmatch( pattern: pattern, string: res, icase: TRUE )){
		set_kb_item( name: "toshiba_printer/detected", value: TRUE );
		set_kb_item( name: "toshiba_printer/http/detected", value: TRUE );
		set_kb_item( name: "toshiba_printer/http/port", value: port );
		url2 = "/TopAccess/Device/Device.htm";
		res2 = http_get_cache( port: port, item: url2 );
		mod = eregmatch( pattern: ">Copier Model.*>TOSHIBA ([^&]+)", string: res2 );
		if( !isnull( mod[1] ) ){
			set_kb_item( name: "toshiba_printer/http/" + port + "/model", value: mod[1] );
			set_kb_item( name: "toshiba_printer/http/" + port + "/concluded", value: mod[0] );
			set_kb_item( name: "toshiba_printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url2, url_only: TRUE ) );
		}
		else {
			cookie = http_get_cookie_from_header( buf: res, pattern: "(Session=[^;]+;)" );
			if( !isnull( cookie ) ){
				url2 = "/contentwebserver";
				data = "<DeviceInformationModel><GetValue><MFP><ModelName></ModelName></MFP></GetValue></DeviceInformationModel>";
				csrfpid = ereg_replace( pattern: "Session=(.*);", string: cookie, replace: "\\1" );
				headers = make_array( "Cookie", cookie += "Locale=en-US,en#q=0.5;", "csrfpId", csrfpid );
				req = http_post_put_req( port: port, url: url2, data: data, add_headers: headers );
				res2 = http_keepalive_send_recv( port: port, data: req );
				mod = eregmatch( pattern: "<ModelName>TOSHIBA ([^<]+)<", string: res2 );
				if(!isnull( mod[1] )){
					set_kb_item( name: "toshiba_printer/http/" + port + "/model", value: mod[1] );
					set_kb_item( name: "toshiba_printer/http/" + port + "/concluded", value: mod[0] );
					set_kb_item( name: "toshiba_printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url2, url_only: TRUE ) );
				}
			}
			else {
				if(!isnull( match[1] )){
					set_kb_item( name: "toshiba_printer/http/" + port + "/model", value: match[1] );
					url2 = "/cgi-bin/dynamic/printer/config/reports/deviceinfo.html";
					headers = make_array( "Cookie", "lexlang=0;" );
					req = http_get_req( port: port, url: url2, add_headers: headers );
					res2 = http_keepalive_send_recv( port: port, data: req );
					vers = eregmatch( pattern: ">Base</p></td><td><p> =  ([^ ]+)", string: res2 );
					if(!isnull( vers[1] )){
						set_kb_item( name: "toshiba_printer/http/" + port + "/fw_version", value: vers[1] );
						set_kb_item( name: "toshiba_printer/http/" + port + "/concluded", value: vers[0] );
						set_kb_item( name: "toshiba_printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url2, url_only: TRUE ) );
					}
				}
			}
		}
		exit( 0 );
	}
}
exit( 0 );

