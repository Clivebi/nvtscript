if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103648" );
	script_version( "2021-10-01T09:48:00+0000" );
	script_tag( name: "last_modification", value: "2021-10-01 09:48:00 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2013-01-30 14:31:24 +0100 (Wed, 30 Jan 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Xerox Printer Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Xerox printer devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("xerox_printers.inc.sc");
require("dump.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
urls = get_xerox_detect_urls();
for url in keys( urls ) {
	pattern = urls[url];
	url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
	buf = http_get_cache( item: url, port: port );
	if(!buf || ( !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && !IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" ) )){
		continue;
	}
	buf = bin2string( ddata: buf, noprint_replacement: "" );
	if( match = eregmatch( pattern: pattern, string: buf, icase: TRUE ) ){
		if(isnull( match[1] )){
			continue;
		}
		if( ContainsString( pattern, "signatureText1" ) ){
			mod = split( buffer: match[1], sep: " ", keep: TRUE );
			model = chomp( mod[0] );
			model = str_replace( string: model, find: "(tm)", replace: "" );
			if( model == "" ) {
				model = chomp( mod[1] );
			}
			else {
				if(IsMatchRegexp( mod[1], "^[0-9]" )){
					model += " " + chomp( mod[1] );
				}
			}
		}
		else {
			model = chomp( match[1] );
			if(!isnull( match[2] )){
				model += " " + chomp( match[2] );
			}
		}
		set_kb_item( name: "xerox/printer/detected", value: TRUE );
		set_kb_item( name: "xerox/printer/http/detected", value: TRUE );
		set_kb_item( name: "xerox/printer/http/port", value: port );
		set_kb_item( name: "xerox/printer/http/" + port + "/model", value: model );
		vers = eregmatch( pattern: "Device Software:</td><td>([0-9.]+)<", string: buf );
		if( !isnull( vers[1] ) ){
			set_kb_item( name: "xerox/printer/http/" + port + "/fw_version", value: vers[1] );
			set_kb_item( name: "xerox/printer/http/" + port + "/concluded", value: vers[0] );
			set_kb_item( name: "xerox/printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
		}
		else {
			vers = eregmatch( pattern: "Version</td><td class=std_2>([0-9]+)<", string: buf );
			if( !isnull( vers[1] ) ){
				set_kb_item( name: "xerox/printer/http/" + port + "/fw_version", value: vers[1] );
				set_kb_item( name: "xerox/printer/http/" + port + "/concluded", value: vers[0] );
				set_kb_item( name: "xerox/printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
			}
			else {
				vers = eregmatch( pattern: "Ver\\. ([0-9A-Z.]+)</h1>", string: buf );
				if( !isnull( vers[1] ) ){
					set_kb_item( name: "xerox/printer/http/" + port + "/fw_version", value: vers[1] );
					set_kb_item( name: "xerox/printer/http/" + port + "/concluded", value: vers[0] );
					set_kb_item( name: "xerox/printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
				}
				else {
					url = "/properties/configuration.php?tab=Status#heading2";
					res = http_get_cache( port: port, item: url );
					vers = eregmatch( pattern: "System Software:</td><td>([0-9.]+)<", string: res );
					if( !isnull( vers[1] ) ){
						set_kb_item( name: "xerox/printer/http/" + port + "/fw_version", value: vers[1] );
						set_kb_item( name: "xerox/printer/http/" + port + "/concluded", value: vers[0] );
						set_kb_item( name: "xerox/printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
					}
					else {
						url = "/aboutprinter.html";
						res = http_get_cache( port: port, item: url );
						vers = eregmatch( pattern: "System Version</td>[^<]+<td>([^<]+)</td>", string: res );
						if(!isnull( vers[1] )){
							set_kb_item( name: "xerox/printer/http/" + port + "/fw_version", value: vers[1] );
							set_kb_item( name: "xerox/printer/http/" + port + "/concluded", value: vers[0] );
							set_kb_item( name: "xerox/printer/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
						}
					}
				}
			}
		}
		exit( 0 );
	}
	else {
		if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" ) && ContainsString( buf, "CentreWare Internet Services" )){
			set_kb_item( name: "xerox/printer/detected", value: TRUE );
			set_kb_item( name: "xerox/printer/http/detected", value: TRUE );
			set_kb_item( name: "xerox/printer/http/port", value: port );
			exit( 0 );
		}
	}
}
exit( 0 );

